package com.netshaper.mobile.security

import android.content.Context
import android.os.UserManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Self-contained Android Keystore + AES-256-GCM token vault.
 *
 * - Zero GMS, zero deprecated `androidx.security:security-crypto` dependencies.
 * - Process-wide [vaultLock] synchronization across UI, ViewModel, and ForegroundService.
 * - Direct-Boot safe (skips Keystore decryption cleanly before CE storage unlock).
 * - Self-heals across Huawei EMUI / Samsung OneUI Keystore alias invalidations instead of crash-looping.
 */
class SecureTokenStore(context: Context) {

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun isCredentialStorageUnlocked(): Boolean {
        val um = appContext.getSystemService(Context.USER_SERVICE) as? UserManager ?: return true
        return runCatching { um.isUserUnlocked }.getOrDefault(true)
    }

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val existing = ks.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        return generateFreshKey()
    }

    private fun generateFreshKey(): SecretKey {
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        keyGen.init(spec)
        return keyGen.generateKey()
    }

    private fun wipeKeyAliasLocked() {
        runCatching {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            if (ks.containsAlias(KEY_ALIAS)) {
                ks.deleteEntry(KEY_ALIAS)
            }
        }
    }

    private fun wipeVaultLocked(markInvalidated: Boolean) {
        wipeKeyAliasLocked()
        prefs.edit().remove(KEY_TOKEN_BLOB).commit()
        if (markInvalidated) {
            keyInvalidatedNotice.set(true)
        }
    }

    private fun isKeystoreInvalidation(t: Throwable): Boolean =
        t is KeyPermanentlyInvalidatedException ||
            t is AEADBadTagException ||
            t is UnrecoverableKeyException ||
            t is KeyStoreException ||
            t is InvalidKeyException ||
            t is ProviderException ||
            t is GeneralSecurityException

    fun saveToken(rawToken: String): Boolean {
        val trimmed = rawToken.trim()
        if (trimmed.isEmpty() || !isCredentialStorageUnlocked()) return false
        synchronized(vaultLock) {
            for (attempt in 0..1) {
                try {
                    val cipher = Cipher.getInstance(TRANSFORMATION)
                    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
                    val iv = cipher.iv
                    val encrypted = cipher.doFinal(trimmed.toByteArray(Charsets.UTF_8))
                    val combined = ByteArray(iv.size + encrypted.size)
                    System.arraycopy(iv, 0, combined, 0, iv.size)
                    System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)
                    val encoded = Base64.encodeToString(combined, Base64.NO_WRAP)
                    keyInvalidatedNotice.set(false)
                    return prefs.edit().putString(KEY_TOKEN_BLOB, encoded).commit()
                } catch (t: Throwable) {
                    if (attempt == 0 && isKeystoreInvalidation(t)) {
                        // Recover cleanly from Huawei/Samsung Keymaster invalidation and retry once.
                        wipeVaultLocked(markInvalidated = false)
                        continue
                    }
                    return false
                }
            }
            return false
        }
    }

    fun loadToken(): String? {
        if (!isCredentialStorageUnlocked()) return null
        synchronized(vaultLock) {
            val encoded = prefs.getString(KEY_TOKEN_BLOB, null) ?: return null
            return try {
                val combined = Base64.decode(encoded, Base64.NO_WRAP)
                if (combined.size <= GCM_IV_LENGTH) {
                    prefs.edit().remove(KEY_TOKEN_BLOB).commit()
                    return null
                }
                val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
                val ciphertext = combined.copyOfRange(GCM_IV_LENGTH, combined.size)
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
                String(cipher.doFinal(ciphertext), Charsets.UTF_8).trim().ifEmpty { null }
            } catch (t: Throwable) {
                val hadInvalidKey = isKeystoreInvalidation(t) || t is IllegalArgumentException
                wipeVaultLocked(markInvalidated = hadInvalidKey)
                null
            }
        }
    }

    fun clearToken() {
        if (!isCredentialStorageUnlocked()) return
        synchronized(vaultLock) {
            prefs.edit().remove(KEY_TOKEN_BLOB).commit()
            keyInvalidatedNotice.set(false)
        }
    }

    fun consumeKeyInvalidatedNotice(): Boolean = keyInvalidatedNotice.getAndSet(false)

    fun hasToken(): Boolean = !loadToken().isNullOrEmpty()

    fun maskedTokenPreview(): String? {
        val token = loadToken() ?: return null
        if (token.length <= 8) return "••••••••"
        val prefix = token.take(4)
        val suffix = token.takeLast(4)
        return "$prefix••••••$suffix"
    }

    companion object {
        private val vaultLock = Any()
        private val keyInvalidatedNotice = AtomicBoolean(false)

        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS = "netshaper_github_token_key"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_BITS = 128
        private const val PREFS_NAME = "netshaper_secure_vault"
        private const val KEY_TOKEN_BLOB = "github_token_gcm_v1"
    }
}
