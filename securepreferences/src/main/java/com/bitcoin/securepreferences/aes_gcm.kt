package com.bitcoin.securepreferences

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
private const val AES_GCM_KEY_ALIAS_SUFFIX = ".aes_gcm_v5"
private const val AES_GCM_KEY_SIZE_BITS = 256
private const val AES_GCM_TAG_SIZE_BITS = 128
private const val AES_GCM_IV_SIZE_BYTES = 12
private const val AES_GCM_JSON_CIPHERTEXT = "ct"
private const val AES_GCM_JSON_IV = "iv"
private const val AES_GCM_KEY_STORE = "AndroidKeyStore"

internal fun encryptUsingAesGcmWithKeyStore(plaintext: String, namespace: String): JSONObject {
    val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateAesGcmKey(namespace))
    cipher.updateAAD(aesGcmAssociatedData(namespace))

    return JSONObject()
        .put(AES_GCM_JSON_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
        .put(
            AES_GCM_JSON_CIPHERTEXT,
            Base64.encodeToString(cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
        )
}

internal fun decryptUsingAesGcmWithKeyStore(encrypted: JSONObject, namespace: String): String {
    val iv = encrypted.requiredBase64(AES_GCM_JSON_IV)
    val ciphertext = encrypted.requiredBase64(AES_GCM_JSON_CIPHERTEXT)
    if (iv.size != AES_GCM_IV_SIZE_BYTES) {
        throw UnrecoverableCiphertextException("Version 5 ciphertext has an invalid IV.")
    }

    val key = try {
        loadAesGcmKey(namespace)
    } catch (e: UnrecoverableKeyException) {
        throw LocalEncryptionKeyLostException("The version 5 local encryption key is unavailable.", e)
    } ?: throw LocalEncryptionKeyLostException("The version 5 local encryption key is missing.")

    return try {
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(AES_GCM_TAG_SIZE_BITS, iv))
        cipher.updateAAD(aesGcmAssociatedData(namespace))
        String(cipher.doFinal(ciphertext), Charsets.UTF_8)
    } catch (e: AEADBadTagException) {
        throw LocalEncryptionKeyLostException(
            "Version 5 ciphertext cannot be authenticated with the local encryption key.",
            e
        )
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw LocalEncryptionKeyLostException("The version 5 local encryption key was invalidated.", e)
    } catch (e: BadPaddingException) {
        // Some AndroidKeyStore providers surface a GCM authentication failure as BadPaddingException.
        throw LocalEncryptionKeyLostException(
            "Version 5 ciphertext cannot be authenticated with the local encryption key.",
            e
        )
    }
}

internal fun deleteAesGcmEncryptionKeyFromKeyStoreIfExists(namespace: String) {
    synchronized(aesGcmKeyLock) {
        val keyStore = KeyStore.getInstance(AES_GCM_KEY_STORE)
        keyStore.load(null, null)
        keyStore.deleteEntry(aesGcmKeyAlias(namespace))
    }
}

private fun getOrCreateAesGcmKey(namespace: String): SecretKey = synchronized(aesGcmKeyLock) {
    loadAesGcmKey(namespace)?.let { return@synchronized it }

    val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AES_GCM_KEY_STORE)
    val keySpec = KeyGenParameterSpec.Builder(
        aesGcmKeyAlias(namespace),
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(AES_GCM_KEY_SIZE_BITS)
        .build()
    keyGenerator.init(keySpec)
    keyGenerator.generateKey()
}

private fun loadAesGcmKey(namespace: String): SecretKey? {
    val keyStore = KeyStore.getInstance(AES_GCM_KEY_STORE)
    keyStore.load(null, null)
    return keyStore.getKey(aesGcmKeyAlias(namespace), null) as? SecretKey
}

private fun JSONObject.requiredBase64(name: String): ByteArray {
    val encoded = optString(name, "")
    if (encoded.isEmpty()) {
        throw UnrecoverableCiphertextException("Version 5 ciphertext is missing $name.")
    }
    return try {
        Base64.decode(encoded, Base64.NO_WRAP)
    } catch (e: IllegalArgumentException) {
        throw UnrecoverableCiphertextException("Version 5 ciphertext contains invalid $name.", e)
    }
}

private fun aesGcmKeyAlias(namespace: String): String = namespace + AES_GCM_KEY_ALIAS_SUFFIX

private fun aesGcmAssociatedData(namespace: String): ByteArray =
    "securepreferences:$namespace:v5".toByteArray(Charsets.UTF_8)

private val aesGcmKeyLock = Any()
