package com.ferrum.vpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore

private const val PREF_FILE = "ferrum_secure_prefs"
private const val KEY_PRIVATE_KEY = "wg_private_key"

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
}
