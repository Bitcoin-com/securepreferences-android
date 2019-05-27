package com.bitcoin.securepreferences


import android.app.KeyguardManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Log


/**
 * throws Exception
 */
class SecurePreferences(context: Context, private val namespace: String) {

    private val TAG = "SecurePreferences"
    private val mApplicationContext: Context =
        context.applicationContext // Just to be sure, might already be an Application Context
    private val mDeviceIsSecure: Boolean
    private val mSharedPreferences: SharedPreferences = context.getSharedPreferences(namespace, Context.MODE_PRIVATE)
    private val mStringEncrypter: SecureStringEncrypter = SecureStringEncrypter(context, namespace)


    class Editor(
        private val editor: SharedPreferences.Editor,
        private val mApplicationContext: Context,
        private val namespace: String,
        private val deviceIsSecure: Boolean,
        private val stringEncrypter: SecureStringEncrypter
    ) {
        private val TAG: String = "SecurePreferencesEditor"

        fun clear() {
            editor.clear()
            deleteAesEncryptionKeyFromKeyStoreIfExists(namespace)
            deleteRsaEncryptionKeyFromKeyStoreIfExists(namespace)
        }

        fun putString(key: String, value: String): Editor {
            val ciphertext: String = stringEncrypter.encryptString(value)
            editor.putString(key, ciphertext)
            return this
        }

        fun remove(key: String) {
            editor.remove(key)
        }

        fun commit(): Boolean {
            return editor.commit()
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
        return Editor(mSharedPreferences.edit(), mApplicationContext, namespace, mDeviceIsSecure, mStringEncrypter)
    }

    fun getString(key: String): String? {
        val pref: String? = mSharedPreferences.getString(key, null)
        if (pref != null) {
            val plaintext: String = mStringEncrypter.decryptString(pref)
            return plaintext
        }

        return null
    }
}