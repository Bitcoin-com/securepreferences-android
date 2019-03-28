package com.bitcoin.securepreferences


import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.lang.Exception
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi


// Keystore Providers
// https://developer.android.com/reference/java/security/KeyStore

// See also:
// StrongBox - https://developer.android.com/training/articles/keystore

private const val KEY_PAIR_GENERATOR_ALGORITHM_RSA: String = "RSA"
private const val KEY_ALIAS_SUFFIX: String = ".rsa"
private const val JSON_CIPHERTEXT: String = "ct"
private const val JSON_VERSION: String = "v"
private const val PROVIDER_ANDROID_KEY_STORE: String = "AndroidKeyStore"
private const val TAG: String = "rsa"

// Mode doesn't make sense for RSA since it only encodes one block
// Key size of 2048 is compatible with StrongBox - https://developer.android.com/training/articles/keystore
private const val VERSION_1_CIPHER: String = "RSA"
private const val VERSION_1_CIPHER_MODE: String = "NONE"
private const val VERSION_1_KEY_SIZE: Int = 2048
private const val VERSION_1_VERSION: Int = 1

internal data class RsaEncryptionResult(val ciphertext: ByteArray, val version: Int)

private data class RsaEncryptionParams(
    val cipher: String,
    val cipherMode: String,
    val keySize: Int,
    val padding: String,
    val version: Int
) {

    val transformation: String = "${cipher}/${cipherMode}/${padding}"

    companion object {
        val currentVersion: RsaEncryptionParams
            get() {
                return forVersion(1)
            }

        fun forVersion(version: Int): RsaEncryptionParams {
            when(version) {
                1 -> {

                    return version1Params()
                }
                else -> throw Exception("RSA encryption version not recognised.")
            }
        }

        private fun version1Params(): RsaEncryptionParams {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return version1ParamsForKeyGenParameterSpec()
            } else {
                return RsaEncryptionParams(VERSION_1_CIPHER, VERSION_1_CIPHER_MODE, VERSION_1_KEY_SIZE, "PKCS1Padding", VERSION_1_VERSION)
            }

        }

        @RequiresApi(Build.VERSION_CODES.M)
        private fun version1ParamsForKeyGenParameterSpec(): RsaEncryptionParams {
            return RsaEncryptionParams(VERSION_1_CIPHER, VERSION_1_CIPHER_MODE, VERSION_1_KEY_SIZE, KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1, VERSION_1_VERSION)
        }
    }

}



private fun createRsaKeyPair(context: Context, keyAlias: String, rsaParams: RsaEncryptionParams): KeyPair {


    // TODO: What if they up grade the OS? - Upgrade existing? - Probably not, too hard to get right.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        return createRsaKeyPairWithKeyGenParameterSpec(keyAlias, rsaParams)
    } else {
        return createRsaKeyPairWithKeyPairGeneratorSpec(context, keyAlias, rsaParams)
    }
}

@RequiresApi(Build.VERSION_CODES.M)
private fun createRsaKeyPairWithKeyGenParameterSpec(keyAlias: String, rsaParams: RsaEncryptionParams): KeyPair {

    /*
    https://developer.android.com/training/articles/keystore

    When generating or importing keys using the KeyStore class, you indicate a preference for storing the key in the StrongBox Keymaster by passing true to the setIsStrongBoxBacked() method in either the KeyGenParameterSpec.Builder class or the KeyProtection.Builder class.

    Note: If the StrongBox Keymaster isn't available for the given algorithm and key size associated with a key, the framework throws a StrongBoxUnavailableException.
    */

    val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_RSA, PROVIDER_ANDROID_KEY_STORE
    )

    val keySpecBuilder: KeyGenParameterSpec.Builder = KeyGenParameterSpec.Builder(
        keyAlias,
        KeyProperties.PURPOSE_DECRYPT
        )
    keySpecBuilder.setEncryptionPaddings(rsaParams.padding)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        try {
            keySpecBuilder.setIsStrongBoxBacked(true)
        } catch (e: StrongBoxUnavailableException) {
            // Continue without StrongBox
        }
    }

    val keySpec: KeyGenParameterSpec = keySpecBuilder.build()
    keyPairGenerator.initialize(keySpec)

    val keyPair: KeyPair = keyPairGenerator.generateKeyPair()
    return keyPair
}


private fun createRsaKeyPairWithKeyPairGeneratorSpec(context: Context, keyAlias: String, rsaParams: RsaEncryptionParams): KeyPair {

    val start = Calendar.getInstance()
    val end = Calendar.getInstance()
    end.add(Calendar.YEAR, 100)

    val keySize: Int = rsaParams.keySize

    // Don't use setEncryptionRequired()
    // https://doridori.github.io/android-security-the-forgetful-keystore/#sthash.UZTvjDTP.ncWnyt7V.dpbs
    val spec: KeyPairGeneratorSpec = KeyPairGeneratorSpec.Builder(context)
        .setAlias(keyAlias)
        .setSubject(X500Principal("CN=${keyAlias}"))
        .setSerialNumber(BigInteger.valueOf(1337))
        .setStartDate(start.time)
        .setEndDate(end.time)
        .setKeySize(keySize)
        .setKeyType(KeyProperties.KEY_ALGORITHM_RSA)
        .build()

    var keyPair: KeyPair? = null
    try {
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(KEY_PAIR_GENERATOR_ALGORITHM_RSA, PROVIDER_ANDROID_KEY_STORE)
        keyPairGenerator.initialize(spec)
        keyPair = keyPairGenerator.generateKeyPair()
    } catch (e: NoSuchAlgorithmException) {
        Log.e(TAG, "Exception when generating RSA key pair.", e)
        throw e
    } catch (e: GeneralSecurityException) {
        Log.e(TAG, "Exception when generating RSA key pair.", e)
        throw e
    }

    return keyPair
}

internal fun decryptWithVersionUsingRsa(json: JSONObject, namespace: String): ByteArray {
    val version: Int? = json.optInt(JSON_VERSION)
    val ciphertextBase64: String? = json.optString(JSON_CIPHERTEXT)

    if (version == null || ciphertextBase64 == null) {
        throw Exception("JSON format for RSA decryption was not recognised.")
    }

    val params: RsaEncryptionParams = RsaEncryptionParams.forVersion(version)
    val transformation: String = params.transformation

    val plaintextBytes: ByteArray = decryptUsingRsa(ciphertextBase64, namespace, transformation)

    return plaintextBytes
}

private fun decryptUsingRsa(ciphertextBase64: String, namespace: String, transformation: String): ByteArray {
    val keyAlias: String = keyAliasFromNamespace(namespace)

    // Load key
    val keyStore: KeyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE)
    keyStore.load(null, null)
    var key: Key? = keyStore.getKey(keyAlias, null)
    if (key == null) {
        throw Exception("RSA key missing.")
    }

    val ciphertextBytes: ByteArray = Base64.decode(ciphertextBase64, Base64.NO_WRAP)
    //Log.d(TAG, "Ciphertext of AES key for decryption: (Byte count: ${ciphertextBytes.count()}) ${ciphertextBytes.toHexString()}")

    val cipher: Cipher = Cipher.getInstance(transformation)
    cipher.init(Cipher.DECRYPT_MODE, key)
    val plaintextBytes: ByteArray = cipher.doFinal(ciphertextBytes)
    return plaintextBytes
}

fun deleteRsaEncryptionKeyFromKeyStoreIfExists(namespace: String) {
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

private fun encryptUsingRsa(context: Context, plaintextBytes: ByteArray, namespace: String): RsaEncryptionResult {
    val keyAlias: String = keyAliasFromNamespace(namespace)
    val rsaParams: RsaEncryptionParams = RsaEncryptionParams.currentVersion

    // load key
    val keyStore: KeyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE)
    keyStore.load(null, null)
    var publicKey: PublicKey? = null
    if (!keyStore.containsAlias(keyAlias)) {
        publicKey = createRsaKeyPair(context, keyAlias, rsaParams).public
    } else {
        publicKey = keyStore.getCertificate(keyAlias).publicKey
    }

    if (publicKey == null) {
        throw Exception("Failed to get or create public key for RSA encryption")
    }


    val transformation: String = rsaParams.transformation
    val cipher: Cipher = Cipher.getInstance(transformation)
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    val ciphertextBytes: ByteArray = cipher.doFinal(plaintextBytes)

    //Log.d(TAG, "Ciphertext of AES key for encryption: (Byte count: ${ciphertextBytes.count()}) ${ciphertextBytes.toHexString()}")

    return RsaEncryptionResult(ciphertextBytes, rsaParams.version)
}

internal fun encryptWithVersionUsingRsa(context: Context, plaintextBytes: ByteArray, namespace: String): JSONObject {

    val encrypted: RsaEncryptionResult = encryptUsingRsa(context, plaintextBytes, namespace)
    val ciphertextBase64: String = Base64.encodeToString(encrypted.ciphertext, Base64.NO_WRAP)
    val json: JSONObject = JSONObject()
    json.put(JSON_CIPHERTEXT, ciphertextBase64)
    json.put(JSON_VERSION, encrypted.version)

    return json;
}

private fun keyAliasFromNamespace(namespace: String): String {
    val keyAlias: String = "${namespace}${KEY_ALIAS_SUFFIX}"
    return keyAlias
}