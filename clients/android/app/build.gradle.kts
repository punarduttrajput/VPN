import java.io.ByteArrayOutputStream
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// ── Rust JNI build ────────────────────────────────────────────────────────────
// Maps Rust target triple → Android ABI directory name
val rustTargets = mapOf(
    "aarch64-linux-android"   to "arm64-v8a",
    "armv7-linux-androideabi" to "armeabi-v7a",
    "x86_64-linux-android"    to "x86_64",
    "i686-linux-android"      to "x86",
)

val rustWorkspaceDir = rootDir.resolve("../../").canonicalFile
val jniOutDir = projectDir.resolve("src/main/jniLibs")
val bindingsKotlinDir = rootDir.resolve("../../crates/client-core/bindings/kotlin").canonicalFile

val buildRustJni by tasks.registering {
    group = "build"
    description = "Cross-compile ferrum-client-core for all Android ABIs"

    doLast {
        val ndkHome = System.getenv("ANDROID_NDK_HOME")
            ?: System.getenv("NDK_HOME")
            ?: error(
                "ANDROID_NDK_HOME not set. " +
                "Install the NDK via Android Studio SDK Manager or set ANDROID_NDK_HOME."
            )
        val hostTag = when {
            org.gradle.internal.os.OperatingSystem.current().isWindows -> "windows-x86_64"
            org.gradle.internal.os.OperatingSystem.current().isMacOsX -> "darwin-x86_64"
            else -> "linux-x86_64"
        }
        val toolchainBin = file("$ndkHome/toolchains/llvm/prebuilt/$hostTag/bin")

        rustTargets.forEach { (triple, abi) ->
            val libOut = jniOutDir.resolve(abi).also { it.mkdirs() }

            val clang = when (triple) {
                "aarch64-linux-android"   -> "aarch64-linux-android35-clang"
                "armv7-linux-androideabi" -> "armv7a-linux-androideabi35-clang"
                "x86_64-linux-android"    -> "x86_64-linux-android35-clang"
                "i686-linux-android"      -> "i686-linux-android35-clang"
                else -> error("Unknown triple: $triple")
            }

            logger.lifecycle("Building Rust for $triple ($abi)…")
            exec {
                workingDir = rustWorkspaceDir
                commandLine(
                    "cargo", "build",
                    "-p", "ferrum-client-core",
                    "--features", "uniffi,data-plane",
                    "--release",
                    "--target", triple,
                )
                environment("CARGO_NET_OFFLINE", "false")
                // Pin the rustup stable toolchain: rustup's nightly here is bleeding-edge
                // enough that curve25519-dalek's nightly-only `simd` backend probe
                // (`feature(stdsimd)`) fails to compile (the feature was renamed/removed).
                environment("RUSTUP_TOOLCHAIN", "stable")
                environment("CC_${triple.replace('-', '_')}", "$toolchainBin/$clang")
                environment("AR_${triple.replace('-', '_')}", "$toolchainBin/llvm-ar")
                environment("CARGO_TARGET_${triple.replace('-', '_').uppercase()}_LINKER", "$toolchainBin/$clang")
                environment("ANDROID_NDK_HOME", ndkHome)
            }

            val soSrc = rustWorkspaceDir.resolve("target/$triple/release/libferrum_client_core.so")
            if (soSrc.exists()) soSrc.copyTo(libOut.resolve("libferrum_client_core.so"), overwrite = true)
            else logger.warn("WARNING: $soSrc not found after build")
        }
    }
}

val generateKotlinBindings by tasks.registering {
    group = "build"
    description = "Generate uniffi Kotlin bindings from the aarch64 cdylib"
    dependsOn(buildRustJni)

    doLast {
        val lib = rustWorkspaceDir
            .resolve("target/aarch64-linux-android/release/libferrum_client_core.so")
        if (!lib.exists()) {
            logger.warn("Skipping Kotlin binding generation: $lib not built yet")
            return@doLast
        }
        exec {
            workingDir = rustWorkspaceDir
            commandLine(
                "cargo", "run",
                "-p", "ferrum-client-core",
                "--features", "uniffi",
                "--bin", "uniffi-bindgen",
                "--",
                "generate",
                "--library", lib.absolutePath,
                "--language", "kotlin",
                "--out-dir", bindingsKotlinDir.absolutePath,
            )
            environment("RUSTUP_TOOLCHAIN", "stable")
            environment("CARGO_NET_OFFLINE", "false")
        }
        logger.lifecycle("Kotlin bindings written to $bindingsKotlinDir")
    }
}

// ── Android ───────────────────────────────────────────────────────────────────

// Load signing credentials from keystore.properties (never committed to git).
val keystoreProps = Properties()
val keystoreFile = rootDir.resolve("keystore.properties")
if (keystoreFile.exists()) keystoreProps.load(keystoreFile.inputStream())

android {
    namespace = "com.ferrum.vpn"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.ferrum.vpn"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    signingConfigs {
        create("release") {
            val ksFile = rootDir.resolve(keystoreProps.getProperty("storeFile", "ferrum-release.jks"))
            if (ksFile.exists()) {
                storeFile     = ksFile
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias      = keystoreProps.getProperty("keyAlias")
                keyPassword   = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }

    buildFeatures { compose = true }

    sourceSets {
        getByName("main") {
            // Include uniffi-generated Kotlin (generated by generateKotlinBindings task)
            kotlin.srcDirs(bindingsKotlinDir.absolutePath)
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    packaging {
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
    }
}

tasks.named("preBuild") { dependsOn(generateKotlinBindings) }

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.security.crypto)
    // JNA is required by uniffi's Kotlin runtime. MUST be the @aar artifact:
    // it bundles libjnidispatch.so for each Android ABI. The plain jar ships only
    // desktop JVM natives, so the first native call crashes with UnsatisfiedLinkError.
    implementation("${libs.jna.get().module}:${libs.jna.get().versionConstraint}@aar")
    debugImplementation(libs.androidx.ui.tooling)
}
