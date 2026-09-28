pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        maven {
            url = uri("https://dl.cloudsmith.io/public/libp2p/jvm-libp2p/maven/")
            content {
                includeGroup("io.libp2p")
            }
        }
        maven {
            url = uri("https://jitpack.io")
            content {
                includeGroup("com.github.multiformats")
            }
        }
        maven {
            url = uri("https://artifacts.consensys.net/public/maven/maven/")
            content {
                includeGroup("tech.pegasys")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "decent-wallet"
include(":interop:android-runtime", ":platforms:android-wallet")
