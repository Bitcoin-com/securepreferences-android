package com.bitcoin.securepreferences

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import org.json.JSONObject


// https://doridori.github.io/android-security-the-forgetful-keystore/#sthash.UZTvjDTP.ncWnyt7V.dpbs

/**
 * throws Exception
 */
class SecureStringEncrypter(context: Context, private val namespace: String) {

    private val TAG = "SecureStringEncrypter"
    private val mApplicationContext: Context =
        context.applicationContext // Just to be sure, might already be an Application Context
    private val mDeviceIsSecure: Boolean

    init {

        var deviceIsSecure: Boolean = false
        val keyguardManager: KeyguardManager? = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        if (keyguardManager != null) {

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                deviceIsSecure = keyguardManager.isDeviceSecure
            } else {
                deviceIsSecure = keyguardManager.isKeyguardSecure
            }
        }

        mDeviceIsSecure = deviceIsSecure
        Log.d(TAG, "Device is secure: ${mDeviceIsSecure}")
    }


    fun encryptString(value: String): String {
        return try {
            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.M -> {
                    encryptStringUsingKeystoreAes(value)
                }
                mDeviceIsSecure -> {
                    encryptStringUsingAesThenKeystoreRsa(value)
                }
                else -> {
                    // TODO: What is the right thing to do here?
                    encryptStringUsingAesThenKeystoreRsa(value)
                }
            }
        } catch (e: Exception) {
            encryptionPassthroughOfString(value)
        }
    }

    private fun encryptStringUsingAesThenKeystoreRsa(value: String): String {
        val aesEncrypted: AesEncryptionResult = encryptUsingAesWithoutKeystore(value)
        //Log.d(TAG, "aesEncrypted: ${aesEncrypted}")

        val rsaEncrypted: JSONObject = encryptWithVersionUsingRsa(mApplicationContext, aesEncrypted.key, namespace)
        val encrypted: JSONObject = JSONObject()
        encrypted.put(JSON_KEY, rsaEncrypted)
        encrypted.put(JSON_VALUE, aesEncrypted.encrypted)

        val container: JSONObject = JSONObject()
        container.put(JSON_VERSION, VERSION_AES_KEY_STORE_RSA)
        container.put(JSON_ENCRYPTED, encrypted)
        val jsonToSave: String = container.toString()

        return jsonToSave
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun encryptStringUsingKeystoreAes(value: String): String {
        val encrypted: JSONObject = encryptUsingAesWithKeystore(value, namespace)
        //Log.d(TAG, "aesEncrypted: ${encrypted}")

        val container: JSONObject = JSONObject()
        container.put(JSON_VERSION, VERSION_KEY_STORE_AES)
        container.put(JSON_ENCRYPTED, encrypted)
        val jsonToSave: String = container.toString()

        return jsonToSave
    }

    fun encryptionPassthroughOfString(value: String): String {
        val container: JSONObject = JSONObject()
        container.put(JSON_VERSION, VERSION_UNENCRYPTED)
        container.put(JSON_VALUE, value)
        val jsonToSave: String = container.toString()

        return jsonToSave
    }

    fun encryptionWithCustomRSA(value: String): String {
        val container: JSONObject = JSONObject()
        container.put(JSON_VERSION, VERSION_CUSTOM_KEY_STORE)
        container.put(JSON_VALUE, value)
        return container.toString()
    }


    fun decryptString(json: String): String {
        val parsed: JSONObject = JSONObject(json)
        val version: Int? = parsed.optInt(JSON_VERSION)
        if (version == null) {
            throw Exception("Format of encrypted data not recognised.")
        }
        when (version) {
            VERSION_UNENCRYPTED -> {
                val value: String? = parsed.optString(JSON_VALUE)
                if (value == null) {
                    throw Exception("Value for encrypted data version $version not found.")
                }
                return value
            }
            VERSION_AES_KEY_STORE_RSA -> {
                val encrypted: JSONObject? = parsed.optJSONObject(JSON_ENCRYPTED)
                if (encrypted == null) {
                    throw Exception("Encrypted value for encrypted data version $version not found.")
                }
                return decryptStringEncryptedUsingAesThenKeyStoreRsa(encrypted)
            }
            VERSION_KEY_STORE_AES -> {
                val encrypted: JSONObject? = parsed.optJSONObject(JSON_ENCRYPTED)
                if (encrypted == null) {
                    throw Exception("Encrypted value for encrypted data version $version not found.")
                }
                return getStringEncryptedUsingKeyStoreAes(encrypted)
            }
            VERSION_CUSTOM_KEY_STORE -> {
                val encrypted = parsed.optJSONObject(JSON_VALUE)
                if (encrypted == null) {
                    throw Exception("Encrypted value for encrypted data version $version not found.")
                }
                return "" // TODO ACTUALLY DO SOMETHING HERE
            }

            else -> throw Exception("Version of encrypted data not recognised.")
        }
    }

    private fun decryptStringEncryptedUsingAesThenKeyStoreRsa(jsonObj: JSONObject): String {
        val rsaEncryptedKey: JSONObject? = jsonObj.optJSONObject(JSON_KEY)
        val aesEncrypted: JSONObject? = jsonObj.optJSONObject(JSON_VALUE)
        if (rsaEncryptedKey == null || aesEncrypted == null) {
            throw Exception("Format of version 1 secure preference not recognised.")
        }

        val aesKey: ByteArray = decryptWithVersionUsingRsa(rsaEncryptedKey, namespace)
        val plaintext: String = decryptUsingAesWithoutKeyStore(aesKey, aesEncrypted)

        return plaintext
    }

    private fun getStringEncryptedUsingKeyStoreAes(json: JSONObject): String {
        val plaintext: String = decryptUsingAesWithKeyStore(json, namespace)
        return plaintext
    }

    companion object {
        private const val JSON_ENCRYPTED: String = "encrypted"
        private const val JSON_KEY: String = "key"
        private const val JSON_VALUE: String = "value"
        private const val JSON_VERSION: String = "v"
        private const val VERSION_UNENCRYPTED: Int = 1
        private const val VERSION_AES_KEY_STORE_RSA: Int = 2
        private const val VERSION_KEY_STORE_AES: Int = 3
        private const val VERSION_CUSTOM_KEY_STORE = 4
    }
}