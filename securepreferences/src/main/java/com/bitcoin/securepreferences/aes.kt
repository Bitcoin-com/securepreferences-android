package com.bitcoin.securepreferences


import android.os.Build
import android.util.Base64

import android.util.Log
import org.json.JSONObject
import java.security.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi


private const val JSON_CIPHERTEXT: String = "ct"
private const val JSON_ENCRYPTED: String = "encrypted"
private const val JSON_IV: String = "iv"
private const val JSON_KEY: String = "key"
private const val JSON_VALUE: String = "value"
private const val JSON_VERSION: String = "v"
private const val KEY_ALIAS_SUFFIX: String = ".aes"
private const val PROVIDER_ANDROID_KEY_STORE: String = "AndroidKeyStore"
private const val TAG: String = "aes"
private const val VERSION_KEY_STORE_128: Int = 2
private const val VERSION_KEY_STORE_256: Int = 3
private const val VERSION_WITHOUT_KEY_STORE: Int = 1

// Compatible with StrongBox
// https://developer.android.com/training/articles/keystore#HardwareSecurityModule

// Available algorithms
// https://developer.android.com/training/articles/keystore
// https://developer.android.com/reference/javax/crypto/Cipher

// Recommended Algorithms
// https://developer.android.com/guide/topics/security/cryptography

// https://doridori.github.io/android-security-the-forgetful-keystore/#sthash.UZTvjDTP.ncWnyt7V.dpbs

internal data class AesEncryptionResult(val key: ByteArray, val encrypted: JSONObject)

private data class AesEncryptionParams(
    val cipher: String,
    val cipherMode: String,
    val padding: String,
    val keyGeneratorAlgorithm: String,
    val keySize: Int,
    val keySpecAlgorithm: String,
    val version: Int
) {

    val transformation: String = "${cipher}/${cipherMode}/${padding}"

    companion object {
        val currentVersion: AesEncryptionParams
            get() {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    return forVersion(VERSION_KEY_STORE_256)
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    return forVersion(VERSION_KEY_STORE_128)
                } else {
                    return forVersion(VERSION_WITHOUT_KEY_STORE)
                }
            }

        fun forVersion(version: Int): AesEncryptionParams {
            when(version) {
                VERSION_WITHOUT_KEY_STORE -> {
                    return forVersionWithoutKeyStore()
                }
                VERSION_KEY_STORE_128 -> {
                    return forVersionKeyStore128()
                }
                VERSION_KEY_STORE_256 -> {
                    return forVersionKeyStore256()
                }
                else -> throw Exception("AES encryption version $version not recognised.")
            }
        }


        private fun forVersionKeyStore128(): AesEncryptionParams {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return AesEncryptionParams(
                    "AES",
                    KeyProperties.BLOCK_MODE_CBC,
                    KeyProperties.ENCRYPTION_PADDING_PKCS7,
                    KeyProperties.KEY_ALGORITHM_AES,
                    128,
                    "AES",
                    VERSION_KEY_STORE_128
                )
            } else {
                throw java.lang.Exception("Encryption version $VERSION_KEY_STORE_128 unsupported on this device.")
            }
        }

        private fun forVersionKeyStore256(): AesEncryptionParams {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                return AesEncryptionParams(
                    "AES",
                    KeyProperties.BLOCK_MODE_CBC,
                    KeyProperties.ENCRYPTION_PADDING_PKCS7,
                    KeyProperties.KEY_ALGORITHM_AES,
                    256,
                    "AES",
                    VERSION_KEY_STORE_256
                )
            } else {
                throw java.lang.Exception("Encryption version $VERSION_KEY_STORE_256 unsupported on this device.")
            }
        }

        fun forVersionWithoutKeyStore(): AesEncryptionParams {
            return AesEncryptionParams(
                "AES",
                "CBC",
                "PKCS5Padding",
                "AES",
                128,
                "AES",
                VERSION_WITHOUT_KEY_STORE
            )
        }

    }

}


private fun createAesKeyWithoutKeystore(params: AesEncryptionParams): SecretKey {
    val keyGenerator: KeyGenerator = KeyGenerator.getInstance(params.keyGeneratorAlgorithm)
    keyGenerator.init(params.keySize, SecureRandom())
    val key: SecretKey = keyGenerator.generateKey()
    return key
}

@RequiresApi(Build.VERSION_CODES.M)
private fun createAesKeyInKeystore(params: AesEncryptionParams, keyAlias: String): SecretKey {
    //Log.d(TAG, "createAesKeyInKeystore()")

    val keyGeneratorWithoutStrongBox: KeyGenerator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES, PROVIDER_ANDROID_KEY_STORE
    )

    val keySpecBuilder: KeyGenParameterSpec.Builder = KeyGenParameterSpec.Builder(
        keyAlias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
    keySpecBuilder
        .setBlockModes(params.cipherMode)
        .setEncryptionPaddings(params.padding)

    val keySpecWithoutStrongBox: KeyGenParameterSpec = keySpecBuilder.build()
    keyGeneratorWithoutStrongBox.init(keySpecWithoutStrongBox)

    var key: SecretKey

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        keySpecBuilder.setIsStrongBoxBacked(true)
        val keySpecWithStrongBox: KeyGenParameterSpec = keySpecBuilder.build()

        val keyGeneratorWithStrongBox: KeyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, PROVIDER_ANDROID_KEY_STORE
        )
        keyGeneratorWithStrongBox.init(keySpecWithStrongBox)

        try {
            key = keyGeneratorWithStrongBox.generateKey()

        } catch (e: StrongBoxUnavailableException) {
            // Continue without StrongBox
            key = keyGeneratorWithoutStrongBox.generateKey()
        }
    } else {
        key = keyGeneratorWithoutStrongBox.generateKey()
    }

    return key

}



internal fun decryptUsingAesWithoutKeyStore(key: ByteArray, json: JSONObject): String {
    val ivBase64: String? = json.optString(JSON_IV)
    val version: Int? = json.optInt(JSON_VERSION)
    val ciphertextBase64: String? = json.optString(JSON_CIPHERTEXT)

    if (ivBase64 != null && version != null && ciphertextBase64 != null) {

        if (version == VERSION_WITHOUT_KEY_STORE) {
            val params: AesEncryptionParams = AesEncryptionParams.forVersion(version)

            val iv: ByteArray = Base64.decode(ivBase64, Base64.NO_WRAP)
            val ivParamSpec: IvParameterSpec = IvParameterSpec(iv)
            val ciphertextBytes: ByteArray = Base64.decode(ciphertextBase64, Base64.NO_WRAP)

            val secretKeySpec: SecretKeySpec = SecretKeySpec(key, params.keySpecAlgorithm)

            val cipher: Cipher = Cipher.getInstance(params.transformation)
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParamSpec)
            val cleartextBytes: ByteArray = cipher.doFinal(ciphertextBytes)
            val cleartext: String = String(cleartextBytes)
            return cleartext
        } else {
            throw Exception("Encrypted value requires KeyStore to decrypt.");
        }

    } else {
        throw Exception("Encrypted value is missing parameters.")
    }
}

internal fun decryptUsingAesWithKeyStore(json: JSONObject, namespace: String): String {
    val encrypted: JSONObject? = json.optJSONObject(JSON_ENCRYPTED)
    val version: Int? = json.optInt(JSON_VERSION)
    if (encrypted == null || version == null) {
        throw Exception("Encrypted value is missing parameters.")
    }


    val params: AesEncryptionParams = AesEncryptionParams.forVersion(version)

    val ivBase64: String? = encrypted.optString(JSON_IV)
    val ciphertextBase64: String? = encrypted.optString(JSON_CIPHERTEXT)
    if (ivBase64 == null|| ciphertextBase64 == null) {
        throw Exception("Encrypted value is missing components.")
    }

    val iv: ByteArray = Base64.decode(ivBase64, Base64.NO_WRAP)
    //Log.d(TAG, "IV: ${iv.toHexString()}")
    val ivParamSpec: IvParameterSpec = IvParameterSpec(iv)
    val ciphertextBytes: ByteArray = Base64.decode(ciphertextBase64, Base64.NO_WRAP)


    // load key
    val keyAlias: String = keyAliasFromNamespace(namespace)
    val keyStore: KeyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE)
    keyStore.load(null, null)
    var key: Key? = keyStore.getKey(keyAlias, null)
    if (key == null) {
        throw Exception("Key missing when decrypting.")
    }

    val cipher: Cipher = Cipher.getInstance(params.transformation)
    cipher.init(Cipher.DECRYPT_MODE, key, ivParamSpec)
    val cleartextBytes: ByteArray = cipher.doFinal(ciphertextBytes)
    val cleartext: String = String(cleartextBytes)
    return cleartext
}

fun deleteAesEncryptionKeyFromKeyStoreIfExists(namespace: String) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val keyAlias: String = keyAliasFromNamespace(namespace)
        val keyStore: KeyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE)
        keyStore.load(null, null)
        try {
            keyStore.deleteEntry(keyAlias)
        } catch (e: KeyStoreException) {
            // KeyStore has not been initialised or entry cannot be removed
        }
    }
}

internal fun encryptUsingAesWithoutKeystore(plaintext: String): AesEncryptionResult {
    val params: AesEncryptionParams = AesEncryptionParams.forVersionWithoutKeyStore()

    val secretKey: SecretKey = createAesKeyWithoutKeystore(params)
    val cipher: Cipher = Cipher.getInstance(params.transformation) //Exception around this?
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    val iv: ByteArray = cipher.iv
    val ciphertext: ByteArray = cipher.doFinal(plaintext.toByteArray())


    val value: JSONObject = JSONObject()
    value.put(JSON_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
    value.put(JSON_VERSION, params.version)
    value.put(JSON_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))

    // https://cryptii.com/pipes/aes-encryption - handy tool for testing

    val hexString: String = iv.toHexString()
    //Log.d(TAG, "iv: ${hexString} plaintext: ${plaintext.toByteArray().toHexString()} key: ${secretKey.encoded.toHexString()} ciphertext: ${ciphertext.toHexString()}")

    val result = JSONObject()
    result.put(JSON_KEY, Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP))
    result.put(JSON_VALUE, value)

    return AesEncryptionResult(secretKey.encoded, value)
}

@RequiresApi(Build.VERSION_CODES.M)
internal fun encryptUsingAesWithKeystore(plaintext: String, namespace: String): JSONObject {
    val params: AesEncryptionParams = AesEncryptionParams.currentVersion

    val key: Key = getOrCreateAesKeystoreKey(params, namespace)
    val cipher: Cipher = Cipher.getInstance(params.transformation) //Exception around this?
    cipher.init(Cipher.ENCRYPT_MODE, key)
    val iv: ByteArray = cipher.iv
    val ciphertext: ByteArray = cipher.doFinal(plaintext.toByteArray())


    val encrypted: JSONObject = JSONObject()
    encrypted.put(JSON_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
    encrypted.put(JSON_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))

    // https://cryptii.com/pipes/aes-encryption - handy tool for testing

    val hexString: String = iv.toHexString()
    //Log.d(TAG, "iv: ${hexString} plaintext: ${plaintext.toByteArray().toHexString()}, key not accessible, ciphertext: ${ciphertext.toHexString()}")

    val result = JSONObject()
    result.put(JSON_VERSION, params.version)
    result.put(JSON_ENCRYPTED, encrypted)

    return result
}

@RequiresApi(Build.VERSION_CODES.M)
private fun getOrCreateAesKeystoreKey(params: AesEncryptionParams, namespace: String): Key {
    val keyAlias: String = keyAliasFromNamespace(namespace)

    val keyStore: KeyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE)
    keyStore.load(null, null)
    var key: Key? = keyStore.getKey(keyAlias, null)
    if (key == null) {
        key = createAesKeyInKeystore(params, keyAlias)
    }
    return key
}

private fun keyAliasFromNamespace(namespace: String): String {
    return "${namespace}${KEY_ALIAS_SUFFIX}"
}