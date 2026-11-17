import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.tasks.OutputDirectory
import java.net.URI
import java.security.MessageDigest
import java.util.Base64

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val walletLoginHost = providers.gradleProperty("walletLoginHost").orElse("login.example.invalid").get()
require(walletLoginHost.length <= 253 && walletLoginHost.matches(Regex("[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")) && ".." !in walletLoginHost) {
    "walletLoginHost must be a DNS hostname only"
}
val walletLoginPort = providers.gradleProperty("walletLoginPort").orElse("443").get().toIntOrNull()
require(walletLoginPort != null && walletLoginPort in 1..65535) { "walletLoginPort must be a TCP port" }
val walletLoginOriginPort = if (walletLoginPort == 443) "" else ":$walletLoginPort"
val qualificationSourceRevision = providers.provider {
    val process = ProcessBuilder("git", "rev-parse", "HEAD")
        .directory(rootProject.projectDir)
        .redirectErrorStream(true)
        .start()
    val revision = process.inputStream.bufferedReader().use { it.readText().trim() }
    require(process.waitFor() == 0 && revision.matches(Regex("[0-9a-f]{40}"))) {
        "Could not determine the exact committed wallet source revision"
    }
    revision
}.get()
val qualificationOfflineValue = providers.gradleProperty("walletQualificationOffline").orElse("false").get()
require(qualificationOfflineValue == "true" || qualificationOfflineValue == "false") {
    "walletQualificationOffline must be exactly true or false"
}
val qualificationTrustProperty = providers.gradleProperty("walletQualificationTrustConfig")
val qualificationSourceTrust = layout.projectDirectory.file("src/qualification/assets/trust_config.json").asFile
val qualificationGeneratedAssets = layout.buildDirectory.dir("generated/qualificationAssets")

abstract class PrepareQualificationTrustConfig : DefaultTask() {
    @get:org.gradle.api.tasks.Input abstract val offline: org.gradle.api.provider.Property<Boolean>
    @get:org.gradle.api.tasks.Input abstract val trustConfigFingerprint: org.gradle.api.provider.Property<String>
    @get:org.gradle.api.tasks.Input abstract val sourceRevision: org.gradle.api.provider.Property<String>
    @get:org.gradle.api.tasks.Optional @get:org.gradle.api.tasks.Input abstract val sourceTrustConfigPath: org.gradle.api.provider.Property<String>
    @get:org.gradle.api.tasks.Input abstract val hasSourceTrustConfig: org.gradle.api.provider.Property<Boolean>
    @get:org.gradle.api.tasks.OutputDirectory abstract val outputDirectory: DirectoryProperty
}

val prepareQualificationTrustConfig = tasks.register("prepareQualificationTrustConfig", PrepareQualificationTrustConfig::class.java) {
    offline.set(qualificationOfflineValue == "true")
    val configuredTrustFile = qualificationTrustProperty.orNull?.let(::file)
    val trustSource = configuredTrustFile ?: qualificationSourceTrust
    trustConfigFingerprint.set(providers.provider {
        trustSource.takeIf { it.isFile }?.let { MessageDigest.getInstance("SHA-256").digest(it.readBytes()).joinToString("") { byte -> "%02x".format(byte) } } ?: "none"
    })
    hasSourceTrustConfig.set(providers.provider { trustSource.isFile })
    sourceTrustConfigPath.set(trustSource.absolutePath)
    sourceRevision.set(qualificationSourceRevision)
    outputDirectory.set(qualificationGeneratedAssets)
    doLast {
        val generated = outputDirectory.get().asFile
        generated.mkdirs()
        generated.resolve("trust_config.json").delete()
        generated.resolve("qualification-provenance.json").writeText(
            "{\"source_revision\":\"${sourceRevision.get()}\",\"trust_config_sha256\":\"${trustConfigFingerprint.get()}\",\"offline\":${offline.get()}}",
            Charsets.UTF_8,
        )
        val source = project.file(sourceTrustConfigPath.get()).takeIf { hasSourceTrustConfig.get() }
        if (source == null) {
            require(offline.get()) { "Qualification trust absent: set walletQualificationTrustConfig or explicitly opt in with -PwalletQualificationOffline=true" }
            return@doLast
        }
        require(!offline.get()) { "Configured qualification trust cannot be built in offline mode" }
        val values = groovy.json.JsonSlurper().parse(source) as? Map<*, *> ?: error("qualification trust config must be a JSON object")
        require(values.keys == setOf("keycloak_display_name", "issuer", "issuer_jwks", "rp")) { "qualification trust config has unexpected or missing fields" }
        fun value(input: Any?, label: String): String {
            val text = input as? String ?: error("qualification trust $label must be a string")
            val lower = text.lowercase()
            require(text.isNotBlank() && text.none { it.code < 0x20 } && listOf(".invalid", ".example", "placeholder", "change_me", "replace_me", "example.com").none(lower::contains)) {
                "qualification trust $label is missing or a placeholder"
            }
            return text
        }
        value(values["keycloak_display_name"], "keycloak_display_name")
        val issuerText = value(values["issuer"], "issuer")
        val issuer = URI(issuerText)
        require(issuer.scheme == "https" && issuer.host == walletLoginHost && issuer.rawUserInfo == null && issuer.rawQuery == null && issuer.rawFragment == null &&
            issuer.rawPath.matches(Regex("/realms/[A-Za-z0-9][A-Za-z0-9._-]{0,62}"))) { "issuer must be the exact configured HTTPS Keycloak realm" }
        val jwks = values["issuer_jwks"] as? Map<*, *> ?: error("issuer_jwks must be a public object")
        require(jwks.keys == setOf("keys")) { "issuer_jwks has invalid fields" }
        val keys = jwks["keys"] as? List<*> ?: error("issuer_jwks.keys must be an array")
        require(keys.isNotEmpty() && keys.size <= 32) { "issuer_jwks.keys must be non-empty and bounded" }
        keys.forEachIndexed { index, raw ->
            val key = raw as? Map<*, *> ?: error("issuer JWK must be an object")
            require(key.keys.all { it in setOf("kid", "kty", "use", "alg", "n", "e", "key_ops") } && key.keys.containsAll(setOf("kid", "kty", "use", "alg", "n", "e"))) {
                "issuer JWK must contain public verification fields only"
            }
            require(key["kty"] == "RSA" && key["use"] == "sig" && key["alg"] == "RS256") { "issuer JWK must be an RS256 verification key" }
            value(key["kid"], "issuer_jwks.keys[$index].kid")
            for (field in listOf("n", "e")) {
                val encoded = value(key[field], "issuer_jwks.keys[$index].$field")
                require(encoded.matches(Regex("[A-Za-z0-9_-]+"))) { "issuer JWK has invalid public RSA parameters" }
                val decoded = Base64.getUrlDecoder().decode(encoded)
                try {
                    require(decoded.isNotEmpty() && decoded[0] != 0.toByte() && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == encoded) {
                        "issuer JWK has invalid public RSA parameters"
                    }
                } finally { decoded.fill(0) }
            }
            if ("key_ops" in key) require(key["key_ops"] == listOf("verify")) { "issuer JWK key_ops must be verify only" }
        }
        val rp = values["rp"] as? Map<*, *> ?: error("rp must be an object")
        require(rp.keys == setOf("client_id", "x509_san_dns", "origin", "response_uri", "trust_anchor_sha256", "rp_client_id")) { "RP registration fields are invalid" }
        val dns = value(rp["x509_san_dns"], "rp.x509_san_dns").lowercase()
        require(dns.length <= 253 && dns.matches(Regex("[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")) && dns.split('.').all { it.isNotEmpty() && it.length <= 63 && !it.startsWith('-') && !it.endsWith('-') }) {
            "RP DNS name is invalid"
        }
        require(value(rp["client_id"], "rp.client_id") == "x509_san_dns:$dns") { "RP client ID must match DNS registration" }
        val origin = URI(value(rp["origin"], "rp.origin"))
        require(origin.scheme == "https" && origin.host == dns && origin.rawUserInfo == null && origin.rawPath.isNullOrEmpty() && origin.rawQuery == null && origin.rawFragment == null && (origin.port == -1 || origin.port == 443)) {
            "RP origin must be its exact HTTPS DNS origin"
        }
        val response = URI(value(rp["response_uri"], "rp.response_uri"))
        require(response.scheme == "https" && response.host == dns && response.rawUserInfo == null && !response.rawPath.isNullOrEmpty() && '%' !in response.rawPath && response.rawQuery == null && response.rawFragment == null && (response.port == -1 || response.port == 443)) {
            "RP response URI must be HTTPS at its registered DNS origin"
        }
        require(value(rp["trust_anchor_sha256"], "rp.trust_anchor_sha256").matches(Regex("[0-9a-f]{64}"))) { "RP trust pin must be lowercase SHA-256 hex" }
        value(rp["rp_client_id"], "rp.rp_client_id")
        source.copyTo(generated.resolve("trust_config.json"), overwrite = true)
    }
}

android {
    namespace = "org.decentwallet.wallet.client"
    compileSdk = 37
    defaultConfig {
        applicationId = "org.decentwallet.wallet.client"
        versionCode = 1
        versionName = "0.1.0-foundation"
        minSdk = 26
        targetSdk = 35
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        manifestPlaceholders["walletLoginHost"] = walletLoginHost
        manifestPlaceholders["walletLoginPort"] = walletLoginPort.toString()
        manifestPlaceholders["walletLoginLabel"] = "Decent Wallet Login"
        manifestPlaceholders["walletApplicationClass"] = ".DebugWalletLoginApplication"
        manifestPlaceholders["walletLoginActivityClass"] = ".WalletLoginActivity"
        buildConfigField("String", "WALLET_LOGIN_ORIGIN", "\"https://$walletLoginHost$walletLoginOriginPort\"")
        buildConfigField("boolean", "WALLET_DEBUG_TLS_ENABLED", "false")
    }
    flavorDimensions += "host"
    productFlavors {
        create("standard") {
            dimension = "host"
            manifestPlaceholders["walletLoginLabel"] = "Decent Wallet Login"
            buildConfigField("boolean", "WALLET_DEBUG_TLS_ENABLED", "true")
        }
        create("qualification") {
            dimension = "host"
            matchingFallbacks += listOf("standard")
            // Qualification builds must use platform TLS, never the instrumentation test CA.
            buildConfigField("boolean", "WALLET_DEBUG_TLS_ENABLED", "false")
            applicationIdSuffix = ".qualification"
            versionName = "0.2.0-qualification"
            versionCode = 2
            manifestPlaceholders["walletLoginLabel"] = "Decent Wallet Qualification"
            manifestPlaceholders["walletLoginActivityClass"] = ".QualificationWalletSetupActivity"
            manifestPlaceholders["walletApplicationClass"] = ".QualificationWalletHostApplication"
            buildConfigField("String", "WALLET_QUALIFICATION_SOURCE_REVISION", "\"$qualificationSourceRevision\"")
        }
    }
    androidComponents {
        beforeVariants(selector().withFlavor("host" to "standard")) { variant -> if (variant.buildType == "release") variant.enable = false }
        onVariants(selector().withFlavor("host" to "qualification")) { variant ->
            variant.sources.assets?.addGeneratedSourceDirectory(prepareQualificationTrustConfig) { it.outputDirectory }
        }
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_1_8) } }
    testOptions { animationsDisabled = true }
    sourceSets {
        getByName("debug") {
            manifest.srcFile("src/debugManifest/AndroidManifest.xml")
            java.setSrcDirs(emptyList<Any>())
            res.setSrcDirs(emptyList<Any>())
            assets.setSrcDirs(emptyList<Any>())
        }
        getByName("standard") {
            manifest.srcFile("src/standardDebug/AndroidManifest.xml")
            java.srcDir("src/standardDebug/kotlin")
            res.srcDir("src/standardDebug/res")
        }
        getByName("androidTest") {
            java.srcDir("src/androidTest/kotlin/org/decentwallet/wallet/client/test")
            assets.srcDir("src/androidTest/assets")
            assets.srcDir("tests/vectors/native-continuation")
            assets.srcDir("tests/vectors/wallet-account-disclosure-v1/vectors")
        }
        getByName("qualification") {
            manifest.srcFile("src/qualification/AndroidManifest.xml")
            java.srcDir("src/qualification/kotlin")
            res.srcDir("src/qualification/res")
            assets.srcDir(qualificationSourceTrust.parentFile)
        }
    }
    packaging {
        resources {
            excludes += "META-INF/INDEX.LIST"
            merges += "META-INF/io.netty.versions.properties"
            pickFirsts += "META-INF/LICENSE.md"
        }
    }
}

dependencies {
    implementation(project(":platforms:android-wallet"))
    implementation("com.fasterxml.jackson.core:jackson-core:2.22.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    androidTestImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("org.bouncycastle:bcpkix-jdk18on:1.86")
}

dependencyLocking { lockAllConfigurations() }
