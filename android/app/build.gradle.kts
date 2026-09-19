plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.ezpi"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.ezpi"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "3.31"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
    }
}

dependencies {
    implementation(files("libs/ezpitun.aar"))
}
