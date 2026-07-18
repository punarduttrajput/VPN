package com.ferrum.vpn

import uniffi.ferrum_client_core.generateKeypair

/**
 * Delegates to the Rust `generate_keypair()` uniffi free function so the same
 * x25519-dalek code path is used on every platform. Returns (privateKeyBase64,
 * publicKeyBase64).
 */
object Curve25519Keygen {
    fun generate(): Pair<String, String> {
        val kp = generateKeypair()
        return kp.privateKey to kp.publicKey
    }
}
