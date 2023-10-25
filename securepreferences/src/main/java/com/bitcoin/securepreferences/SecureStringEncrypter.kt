package com.bitcoin.securepreferences

import android.app.KeyguardManager
import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import org.json.JSONObject
import org.spongycastle.util.encoders.Base64
import java.util.*


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
        val keyguardManager: KeyguardManager? =
            context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        if (keyguardManager != null) {
            deviceIsSecure = keyguardManager.isDeviceSecure
        }

        mDeviceIsSecure = deviceIsSecure
        Log.d(TAG, "Device is secure: $mDeviceIsSecure")
    }

    @Synchronized
    fun encryptString(
        value: String,
        plainTextFallback: Boolean = false,
        versionOverride: Int? = null
    ): String {
        return try {
            when (versionOverride) {
                VERSION_UNENCRYPTED -> encryptionPassthroughOfString(value)
                VERSION_KEY_STORE_AES -> {
                    encryptStringUsingKeystoreAes(value)
                }
                VERSION_AES_KEY_ENCRYPTED_PREFERENCE -> encryptStringUsingAesThenEncryptedPreference(
                    value
                )
                VERSION_AES_KEY_STORE_RSA -> encryptStringUsingAesThenKeystoreRsa(value)
                else -> encryptString(value)
            }
        } catch (e: Exception) {
            if (plainTextFallback) {
                encryptionPassthroughOfString(value)
            } else {
                throw e
            }
        }

    }

    @Synchronized
    fun encryptString(value: String): String {
        return encryptStringUsingKeystoreAes(value)
    }

    val encryptedSharedPreference: SharedPreferences by lazy {
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        EncryptedSharedPreferences.create(
            "private_pref",
            masterKeyAlias,
            mApplicationContext,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private fun encryptStringUsingAesThenEncryptedPreference(value: String): String {
        val aesEncrypted: AesEncryptionResult = encryptUsingAesWithoutKeystore(value)
        val encrypted = JSONObject()


        val sharedPreferences = encryptedSharedPreference
        val keyRef = UUID.randomUUID().toString()
        sharedPreferences.edit().putString(keyRef, Base64.toBase64String(aesEncrypted.key)).commit()
        encrypted.put(JSON_KEY, keyRef)
        encrypted.put(JSON_VALUE, aesEncrypted.encrypted)

        val container = JSONObject()
        container.put(JSON_VERSION, VERSION_AES_KEY_ENCRYPTED_PREFERENCE)
        container.put(JSON_ENCRYPTED, encrypted)

        return container.toString()
    }

    private fun encryptStringUsingAesThenKeystoreRsa(value: String): String {
        val aesEncrypted: AesEncryptionResult = encryptUsingAesWithoutKeystore(value)

        val rsaEncrypted: JSONObject =
            encryptWithVersionUsingRsa(mApplicationContext, aesEncrypted.key, namespace)
        val encrypted = JSONObject()
        encrypted.put(JSON_KEY, rsaEncrypted)
        encrypted.put(JSON_VALUE, aesEncrypted.encrypted)

        val container = JSONObject()
        container.put(JSON_VERSION, VERSION_AES_KEY_STORE_RSA)
        container.put(JSON_ENCRYPTED, encrypted)

        return container.toString()
    }

    private fun encryptStringUsingKeystoreAes(value: String): String {
        val encrypted: JSONObject = encryptUsingAesWithKeystore(value, namespace)
        //Log.d(TAG, "aesEncrypted: ${encrypted}")

        val container: JSONObject = JSONObject()
        container.put(JSON_VERSION, VERSION_KEY_STORE_AES)
        container.put(JSON_ENCRYPTED, encrypted)

        return container.toString()
    }

    private fun encryptionPassthroughOfString(value: String): String {
        val container: JSONObject = JSONObject()
        container.put(JSON_VERSION, VERSION_UNENCRYPTED)
        container.put(JSON_VALUE, value)

        return container.toString()
    }

    fun getEncryptionType(json: String): Int {
        val parsed = JSONObject(json)
        return parsed.optInt(JSON_VERSION)
    }

    @Synchronized
    fun decryptString(json: String): String {
        val parsed = JSONObject(json)
        when (val version: Int = parsed.optInt(JSON_VERSION)) {
            VERSION_UNENCRYPTED -> {
                return parsed.optString(JSON_VALUE)
                    ?: throw Exception("Value for encrypted data version $version not found.")
            }
            VERSION_AES_KEY_STORE_RSA -> {
                val encrypted: JSONObject = parsed.optJSONObject(JSON_ENCRYPTED)
                    ?: throw Exception("Encrypted value for encrypted data version $version not found.")
                return decryptStringEncryptedUsingAesThenKeyStoreRsa(encrypted)
            }
            VERSION_KEY_STORE_AES -> {
                val encrypted: JSONObject = parsed.optJSONObject(JSON_ENCRYPTED)
                    ?: throw Exception("Encrypted value for encrypted data version $version not found.")
                return getStringEncryptedUsingKeyStoreAes(encrypted)
            }
            VERSION_AES_KEY_ENCRYPTED_PREFERENCE -> {
                val encrypted = parsed.optJSONObject(JSON_ENCRYPTED)
                    ?: throw Exception("Encrypted value for encrypted data version $version not found.")
                return decryptStringEncryptedUsingAesEncryptedSharedPreference(encrypted)
            }

            else -> throw Exception("Version of encrypted data not recognised.")
        }
    }

    private fun decryptStringEncryptedUsingAesEncryptedSharedPreference(jsonObj: JSONObject): String {
        val keyRef = jsonObj.optString(JSON_KEY)
        val aesEncrypted = jsonObj.optJSONObject(JSON_VALUE)
        if (aesEncrypted == null) {
            throw Exception("Fetching JSON failed: keyRef: $keyRef EncryptedValue: $aesEncrypted")
        }
        val sharedPreferences = encryptedSharedPreference
        val base64Key = sharedPreferences.getString(keyRef, null)

        if (base64Key == null) {
            throw Exception("Unable  to find key: $base64Key")
        }

        val aesKey = Base64.decode(base64Key)

        return decryptUsingAesWithoutKeyStore(aesKey, aesEncrypted)
    }

    private fun decryptStringEncryptedUsingAesThenKeyStoreRsa(jsonObj: JSONObject): String {
        val rsaEncryptedKey: JSONObject? = jsonObj.optJSONObject(JSON_KEY)
        val aesEncrypted: JSONObject? = jsonObj.optJSONObject(JSON_VALUE)
        if (rsaEncryptedKey == null || aesEncrypted == null) {
            throw Exception("Format of version 1 secure preference not recognised.")
        }

        val aesKey: ByteArray = decryptWithVersionUsingRsa(rsaEncryptedKey, namespace)

        return decryptUsingAesWithoutKeyStore(aesKey, aesEncrypted)
    }

    private fun getStringEncryptedUsingKeyStoreAes(json: JSONObject): String {
        return decryptUsingAesWithKeyStore(json, namespace)
    }

    companion object {
        private const val JSON_ENCRYPTED: String = "encrypted"
        private const val JSON_KEY: String = "key"
        private const val JSON_VALUE: String = "value"
        private const val JSON_VERSION: String = "v"
        const val VERSION_UNENCRYPTED: Int = 1
        const val VERSION_AES_KEY_STORE_RSA: Int = 2
        const val VERSION_KEY_STORE_AES: Int = 3
        const val VERSION_AES_KEY_ENCRYPTED_PREFERENCE = 4
    }
}