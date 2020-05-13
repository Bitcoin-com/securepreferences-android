package com.bitcoin.securepreferences

import org.spongycastle.util.encoders.Base64
import java.nio.charset.Charset
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher


private const val KEY_ALIAS_SUFFIX: String = ".custom-rsa"


private const val PROVIDER_ANDROID_KEY_STORE: String = "AndroidKeyStore"

private const val OUR_PASSWORD: String = "A_PASSWORD"

class CustomRsa(private val keyStore: KeyStore) {

    fun decrypt(text: String, namespace: String): String {
        val keyAlias: String = keyAliasFromNamespace(namespace)
        keyStore.load(null, null)
        val key: Key = keyStore.getKey(keyAlias, null) ?: throw Exception("Key missing when decrypting.")
        return decrypt(text, key)
    }


    fun encrypt(text: String, namespace: String): String {
        val keyAlias: String = keyAliasFromNamespace(namespace)
        keyStore.load(null, null)
        val key: Key? = keyStore.getKey(keyAlias, null)

        if (key == null) {
            val keys = KeyPairGenerator.getInstance("RSA")
            val keyPair: KeyPair = keys.generateKeyPair()
            //SAVE keyPair.private somewhere
            return encrypt(text, keyPair.public)
        }
        return encrypt(text, key)
    }


    private fun encrypt(text: String, key: Key): String {
        val encryptedText: String
        val cipherText: ByteArray = encrypt(text.toByteArray(charset("UTF-8")), key)
        return Base64.toBase64String(cipherText)
    }

    private fun encrypt(text: ByteArray, key: Key): ByteArray {
        val cipher: Cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(text)
    }

    private fun decrypt(text: String, key: Key): String {
        val decryptedText: ByteArray = decrypt(Base64.decode(text), key)
        return String(decryptedText, Charset.forName("UTF-8"))
    }

    private fun decrypt(text: ByteArray, key: Key): ByteArray {
        val cipher: Cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.DECRYPT_MODE, key)
        return cipher.doFinal(text)
    }

    private fun keyAliasFromNamespace(namespace: String): String {
        return "${namespace}${KEY_ALIAS_SUFFIX}"
    }
}


