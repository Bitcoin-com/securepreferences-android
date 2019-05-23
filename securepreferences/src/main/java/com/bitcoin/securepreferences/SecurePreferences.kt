package com.bitcoin.securepreferences


import android.app.KeyguardManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import org.json.JSONObject
import java.lang.Exception


// https://doridori.github.io/android-security-the-forgetful-keystore/#sthash.UZTvjDTP.ncWnyt7V.dpbs

private const val JSON_ENCRYPTED: String = "encrypted"
private const val JSON_KEY: String = "key"
private const val JSON_VALUE: String = "value"
private const val JSON_VERSION: String = "v"
private const val VERSION_UNENCRYPTED: Int = 1
private const val VERSION_AES_KEY_STORE_RSA: Int = 2
private const val VERSION_KEY_STORE_AES: Int = 3

/**
 * throws Exception
 */
class SecurePreferences(context: Context, private val namespace: String) {

    private val TAG = "SecurePreferences"
    private val mApplicationContext: Context = context.applicationContext // Just to be sure, might already be an Application Context
    private val mDeviceIsSecure: Boolean
    private val mSharedPreferences: SharedPreferences = context.getSharedPreferences(namespace, Context.MODE_PRIVATE)



    class Editor(private val editor: SharedPreferences.Editor, private val mApplicationContext: Context, private val namespace: String, private val deviceIsSecure: Boolean) {
        private val TAG: String = "SecurePreferencesEditor"

        fun clear() {
            editor.clear()
            deleteAesEncryptionKeyFromKeyStoreIfExists(namespace)
            deleteRsaEncryptionKeyFromKeyStoreIfExists(namespace)
        }

        fun putString(key: String, value: String): Editor {

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                putStringUsingKeystoreAes(key, value)
            } else if (deviceIsSecure) {
                putStringUsingAesThenKeystoreRsa(key, value)
            } else {
                // TODO: What is the right thing to do here?
                putStringUsingAesThenKeystoreRsa(key, value)
            }

            return this
        }

        fun remove(key: String) {
            editor.remove(key)
        }

        fun commit(): Boolean {
            return editor.commit()
        }

        private fun putStringUsingAesThenKeystoreRsa(key: String, value: String) {
            val aesEncrypted: AesEncryptionResult = encryptUsingAesWithoutKeystore(value, namespace)
            //Log.d(TAG, "aesEncrypted: ${aesEncrypted}")

            val rsaEncrypted: JSONObject = encryptWithVersionUsingRsa(mApplicationContext, aesEncrypted.key, namespace)
            val encrypted: JSONObject = JSONObject()
            encrypted.put(JSON_KEY, rsaEncrypted)
            encrypted.put(JSON_VALUE, aesEncrypted.encrypted)

            val container: JSONObject = JSONObject()
            container.put(JSON_VERSION, VERSION_AES_KEY_STORE_RSA)
            container.put(JSON_ENCRYPTED, encrypted)
            val jsonToSave: String = container.toString()

            //Log.d(TAG, "Putting: \"${jsonToSave}\"")
            editor.putString(key, jsonToSave)
        }

        @RequiresApi(Build.VERSION_CODES.M)
        private fun putStringUsingKeystoreAes(key: String, value: String) {
            val encrypted: JSONObject = encryptUsingAesWithKeystore(value, namespace)
            //Log.d(TAG, "aesEncrypted: ${encrypted}")

            val container: JSONObject = JSONObject()
            container.put(JSON_VERSION, VERSION_KEY_STORE_AES)
            container.put(JSON_ENCRYPTED, encrypted)
            val jsonToSave: String = container.toString()

            //Log.d(TAG, "Putting: \"${jsonToSave}\"")
            editor.putString(key, jsonToSave)
        }

        private fun putStringWithoutEncryption(key: String, value: String) {
            val container: JSONObject = JSONObject()
            container.put(JSON_VERSION, VERSION_UNENCRYPTED)
            container.put(JSON_VALUE, value)
            val jsonToSave: String = container.toString()

           //Log.d(TAG, "Putting: \"${jsonToSave}\"")
            editor.putString(key, jsonToSave)
        }
    }


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

    fun edit(): Editor {
        return Editor(mSharedPreferences.edit(), mApplicationContext, namespace, mDeviceIsSecure)
    }



    fun getString(key: String): String? {
        val pref: String? = mSharedPreferences.getString(key, null)
        if (pref != null) {
            val json: JSONObject = JSONObject(pref)
            val version: Int? = json.optInt(JSON_VERSION)
            if (version == null) {
                throw Exception("Format of secure preference not recognised.")
            }
            when(version) {
                VERSION_UNENCRYPTED -> {
                    val value: String? = json.optString(JSON_VALUE)
                    if (value == null) {
                        throw Exception("Value for secure preference version $version not found.")
                    }
                    return value
                }
                VERSION_AES_KEY_STORE_RSA -> {
                    val encrypted: JSONObject? = json.optJSONObject(JSON_ENCRYPTED)
                    if (encrypted == null) {
                        throw Exception("Encrypted value for secure preference version $version not found.")
                    }
                    return getStringEncryptedUsingAesThenKeyStoreRsa(encrypted)
                }
                VERSION_KEY_STORE_AES -> {
                    val encrypted: JSONObject? = json.optJSONObject(JSON_ENCRYPTED)
                    if (encrypted == null) {
                        throw Exception("Encrypted value for secure preference version $version not found.")
                    }
                    return getStringEncryptedUsingKeyStoreAes(encrypted)
                }
                else -> throw Exception("Version of secure preference not recognised.")
            }
        }

        return null
    }

    private fun getStringEncryptedUsingAesThenKeyStoreRsa(json: JSONObject): String {
        val rsaEncryptedKey: JSONObject? = json.optJSONObject(JSON_KEY)
        val aesEncrypted: JSONObject? = json.optJSONObject(JSON_VALUE)
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

}