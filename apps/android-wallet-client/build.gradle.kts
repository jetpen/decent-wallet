import org.jetbrains.kotlin.gradle.dsl.JvmTarget

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
        buildConfigField("String", "WALLET_LOGIN_ORIGIN", "\"https://$walletLoginHost:$walletLoginPort\"")
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_1_8) } }
    testOptions { animationsDisabled = true }
    sourceSets {
        getByName("androidTest") {
            assets.srcDir(rootProject.file("tests/vectors/native-continuation"))
            assets.srcDir(rootProject.file("tests/vectors/wallet-account-disclosure-v1/vectors"))
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
