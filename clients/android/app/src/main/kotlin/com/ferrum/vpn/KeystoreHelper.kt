package com.ferrum.vpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore

private const val PREF_FILE = "ferrum_secure_prefs"
private const val KEY_PRIVATE_KEY = "wg_private_key"
private const val KEY_OIDC_TOKEN = "oidc_token"

/**
 * Stores the WireGuard private key in EncryptedSharedPreferences backed by
 * the Android Keystore. The AES-256-GCM master key never leaves secure hardware
 * on devices that support StrongBox.
 */
class KeystoreHelper(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .setUserAuthenticationRequired(false)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        PREF_FILE,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun savePrivateKey(key: String) {
        prefs.edit().putString(KEY_PRIVATE_KEY, key).apply()
    }

    fun loadPrivateKey(): String? = prefs.getString(KEY_PRIVATE_KEY, null)

    fun hasPrivateKey(): Boolean = prefs.contains(KEY_PRIVATE_KEY)

    fun clearPrivateKey() {
        prefs.edit().remove(KEY_PRIVATE_KEY).apply()
    }

    /** The OIDC bearer token the coordinator's gRPC endpoint requires on every
     *  RPC when it's built with `--oidc-issuer` (see FfiFerrumClient.setToken). */
    fun saveToken(token: String) {
        prefs.edit().putString(KEY_OIDC_TOKEN, token).apply()
    }

    fun loadToken(): String? = prefs.getString(KEY_OIDC_TOKEN, null)

    fun hasToken(): Boolean = prefs.contains(KEY_OIDC_TOKEN)

    fun clearToken() {
        prefs.edit().remove(KEY_OIDC_TOKEN).apply()
    }
}
