package com.bitcoin.securepreferences

import android.util.Base64
import java.nio.charset.Charset
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher


class CustomRsa {
    companion object {
        fun encrypt(text: String, key: PublicKey): String? {
            val encryptedText: String
            val cipherText = encrypt(text.toByteArray(charset("UTF-8")), key)
            encryptedText = Base64.encodeToString(cipherText, 0)
            return encryptedText
        }

        private fun encrypt(text: ByteArray, key: PublicKey): ByteArray? {

            val cipher: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            // encrypt the plaintext using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return cipher.doFinal(text)
        }


        fun decrypt(text: String, key: PrivateKey): String? {
            val result: String
            // decrypt the text using the private key
            val decryptedText: ByteArray = decrypt(Base64.decode(text, 0), key)
            result = String(decryptedText, Charset.forName("UTF-8"))
            return result
        }

        private fun decrypt(text: ByteArray, key: PrivateKey): ByteArray {
            var dectyptedText: ByteArray? = null
            // decrypt the text using the private key
            val cipher: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(Cipher.DECRYPT_MODE, key)
            dectyptedText = cipher.doFinal(text)
            return dectyptedText
        }

    }
}


