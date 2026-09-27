import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.decentwallet.interop.androidruntime"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    sourceSets {
        getByName("androidTest") {
            assets.srcDir(rootProject.file("tests/vectors"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    testOptions {
        animationsDisabled = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
    }
}

val sharedVerifierSources = files(
    rootProject.file("interop/kotlin/src/test/kotlin/org/decentwallet/interop/WalletContainerV2Verifier.kt"),
    rootProject.file("interop/kotlin/src/test/kotlin/org/decentwallet/interop/WireJson.kt"),
)

tasks.withType<KotlinCompile>().configureEach {
    if (name == "compileDebugKotlin" || name == "compileReleaseKotlin") {
        setSource(sharedVerifierSources)
    }
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("com.fasterxml.jackson.core:jackson-core:2.22.2")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("junit:junit:4.13.2")
}

dependencyLocking {
    lockAllConfigurations()
}
