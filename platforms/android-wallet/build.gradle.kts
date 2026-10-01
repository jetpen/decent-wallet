import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

val registryTestPeer = providers.environmentVariable("DECENT_REGISTRY_TEST_PEER").orElse("")
val registryTestReadbackPeer = providers.environmentVariable("DECENT_REGISTRY_TEST_READBACK_PEER").orElse("")
val issue18AndroidTestClass = providers.gradleProperty("issue18AndroidTestClass").orElse("")

android {
    namespace = "org.decentwallet.wallet.android"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["decentRegistryTestPeer"] = registryTestPeer.get()
        testInstrumentationRunnerArguments["decentRegistryTestReadbackPeer"] = registryTestReadbackPeer.get()
        issue18AndroidTestClass.orNull?.takeIf(String::isNotBlank)?.let {
            testInstrumentationRunnerArguments["class"] = it
        }
    }

    sourceSets {
        getByName("test") {
            resources.srcDir(rootProject.file("tests/vectors"))
            resources.srcDir(rootProject.file("tests/fixtures"))
        }
        getByName("androidTest") {
            assets.srcDir(rootProject.file("tests/vectors"))
            assets.srcDir(rootProject.file("tests/fixtures"))
        }
    }

    packaging {
        resources {
            excludes += "META-INF/INDEX.LIST"
            merges += "META-INF/io.netty.versions.properties"
            pickFirsts += "META-INF/LICENSE.md"
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

tasks.withType<KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
    }
}

tasks.withType<Test>().configureEach {
    systemProperty("decent.registry.test.peer", registryTestPeer.get())
    systemProperty("decent.registry.test.readback.peer", registryTestReadbackPeer.get())
}

tasks.matching { it.name == "connectedDebugAndroidTest" }.configureEach {
    inputs.property("decentRegistryTestPeer", registryTestPeer)
    inputs.property("decentRegistryTestReadbackPeer", registryTestReadbackPeer)
    inputs.property("issue18AndroidTestClass", issue18AndroidTestClass)
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
    implementation("org.bouncycastle:bcutil-jdk18on:1.86")
    implementation("com.fasterxml.jackson.core:jackson-core:2.22.2")
    implementation("com.google.protobuf:protobuf-java:3.25.5")
    implementation("io.libp2p:jvm-libp2p:1.3.7-RELEASE") {
        exclude(group = "io.netty", module = "netty-codec-native-quic")
        exclude(group = "io.netty", module = "netty-tcnative-boringssl-static")
        exclude(group = "io.netty", module = "netty-transport-classes-epoll")
    }

    testImplementation("junit:junit:4.13.2")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("junit:junit:4.13.2")
}

dependencyLocking {
    lockAllConfigurations()
}
