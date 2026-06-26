# uniffi JNI bridge — keep all generated scaffolding
-keep class uniffi.** { *; }
-keep class com.sun.jna.** { *; }
-dontwarn com.sun.jna.**

# Rust library name
-keep class com.plasmacomp.ferrum.** { *; }
