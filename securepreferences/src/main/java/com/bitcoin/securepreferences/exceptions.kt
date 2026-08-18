package com.bitcoin.securepreferences

/**
 * Ciphertext that can never be decrypted on this device again, because the key material that
 * protected it is gone. Callers should re-derive the value from a backup rather than retry.
 */
open class UnrecoverableCiphertextException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

/**
 * The encrypted preference store could not be opened even after being reset, so nothing can be
 * encrypted or decrypted through it. Unlike [UnrecoverableCiphertextException] this may clear up,
 * for example once a device with a misbehaving KeyStore is rebooted.
 */
class EncryptedPreferenceUnavailableException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)
