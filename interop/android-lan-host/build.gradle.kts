import org.jetbrains.kotlin.gradle.dsl.JvmTarget
plugins {
  id("com.android.application")
  id("org.jetbrains.kotlin.android")
}
android {
  namespace = "org.decentwallet.interop.lanhost"
  compileSdk = 37
  buildToolsVersion = "37.0.0"
  defaultConfig {
    applicationId = "org.decentwallet.interop.lanhost"
    minSdk = 26
    targetSdk = 37
    versionCode = 1
    versionName = "test-only"
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
  }
  sourceSets.getByName("main").assets.srcDir(rootProject.file("tests/vectors"))
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
  }
  packaging {
    resources.excludes += "META-INF/INDEX.LIST"
    resources.merges += "META-INF/io.netty.versions.properties"
    resources.pickFirsts += "META-INF/LICENSE.md"
  }
  testOptions.animationsDisabled = true
}
kotlin.compilerOptions.jvmTarget.set(JvmTarget.JVM_1_8)
dependencies {
  implementation(project(":platforms:android-wallet"))
  testImplementation("junit:junit:4.13.2")
  androidTestImplementation("androidx.test:runner:1.7.0")
  androidTestImplementation("junit:junit:4.13.2")
}
dependencyLocking { lockAllConfigurations() }
