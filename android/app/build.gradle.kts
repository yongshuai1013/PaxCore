plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Pinned signing key (CI secrets): AGP's default debug key is
// generated fresh on every CI runner, so unpinned builds carry a
// different signature each time and Android refuses overlay
// installs. When all four env vars are present (CI decodes the
// keystore from secrets), builds use the project's permanent key;
// local builds without them keep the default debug signature.
val paxcoreKeystorePath = System.getenv("PAXCORE_KEYSTORE_PATH")
val paxcoreKeystorePassword = System.getenv("PAXCORE_KEYSTORE_PASSWORD")
val paxcoreKeyAlias = System.getenv("PAXCORE_KEY_ALIAS")
val paxcoreKeyPassword = System.getenv("PAXCORE_KEY_PASSWORD")
val usePaxcoreSigning = listOf(
    paxcoreKeystorePath, paxcoreKeystorePassword, paxcoreKeyAlias, paxcoreKeyPassword
).all { !it.isNullOrBlank() }

android {
    namespace = "com.yongshuai.paxcore"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.yongshuai.paxcore"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    signingConfigs {
        if (usePaxcoreSigning) {
            create("paxcore") {
                storeFile = file(paxcoreKeystorePath!!)
                storePassword = paxcoreKeystorePassword
                keyAlias = paxcoreKeyAlias
                keyPassword = paxcoreKeyPassword
            }
        }
    }

    buildTypes {
        debug {
            if (usePaxcoreSigning) {
                signingConfig = signingConfigs.getByName("paxcore")
            }
        }
        release {
            isMinifyEnabled = false
        }
    }

    packaging {
        jniLibs {
            // libpaxcore.so ships in jniLibs and must land as a real
            // executable file in nativeLibraryDir so the shell can
            // exec it. Without legacy packaging it stays inside the
            // APK and there is no executable path.
            useLegacyPackaging = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}
