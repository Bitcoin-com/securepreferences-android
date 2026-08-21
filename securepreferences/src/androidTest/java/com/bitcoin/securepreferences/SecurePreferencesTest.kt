package com.bitcoin.securepreferences

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Before
import org.junit.Test

import org.junit.Assert.*
import org.junit.runner.RunWith
import org.json.JSONObject


// This crashes - maybe because there is no app for the context?
@RunWith(AndroidJUnit4::class)
class SecurePreferencesTest {
    private var TAG: String = "SecurePreferencesTest"
    lateinit var mPrefs: SecurePreferences

    @Before
    fun setUp() {
        val context: Context? = ApplicationProvider.getApplicationContext()
        if (context != null) {
            mPrefs = SecurePreferences(context, "ns")
            val editor: SecurePreferences.Editor = mPrefs.edit()
            editor.clear()
            editor.commit()
        } else {
            Log.e(TAG, "No context.")
        }
    }


    @After
    fun tearDown() {
        val editor: SecurePreferences.Editor = mPrefs.edit()
        editor.clear()
        editor.commit()
    }

    @Test
    fun givenStringWasSaved_whenStringIsRemovedThenLoaded_thenStringIsNull() {
        // GIVEN
        val editor: SecurePreferences.Editor = mPrefs.edit()
        editor.putString("key3", "value3")
        assertTrue(editor.commit())
        val savedValue: String? = mPrefs.getString("key3")
        assertNotNull(savedValue)
        if (savedValue != null) {
            assertEquals("value3", savedValue)
        }

        // WHEN
        editor.remove("key3")
        assertTrue(editor.commit())
        val retrieved: String? = mPrefs.getString("key3")

        // THEN
        assertNull(retrieved)
    }

    @Test
    fun givenStringNeverSaved_whenWhenStringLoaded_thenStringIsNull() {
        // GIVEN

        // WHEN
        val retrieved: String? = mPrefs.getString("key0")

        // THEN
        assertNull(retrieved)
    }

    @Test
    fun givenStringWasSaved_whenPrefsClearedAndStringLoaded_thenStringIsNull() {
        // GIVEN
        val editor: SecurePreferences.Editor = mPrefs.edit()
        editor.putString("key1", "value1")
        assertTrue(editor.commit())



        // WHEN
        editor.clear()
        assertTrue(editor.commit())
        val retrieved: String? = mPrefs.getString("key1")

        // THEN
        assertNull(retrieved)
    }

    @Test
    fun givenStringWasSaved_whenStringLoaded_thenStringIsEqual() {
        // GIVEN
        val editor: SecurePreferences.Editor = mPrefs.edit()
        editor.putString("key2", "value2")
        assertTrue(editor.commit())

        // WHEN
        val retrieved: String? = mPrefs.getString("key2")

        // THEN
        assertNotNull(retrieved)
        assertEquals(retrieved, "value2")

    }

    @Test
    fun defaultEncryptionRemainsVersion3AndRoundTrips() {
        val encrypter = SecureStringEncrypter(
            ApplicationProvider.getApplicationContext(),
            "version3-round-trip"
        )

        val ciphertext = encrypter.encryptString("secret")

        assertEquals(SecureStringEncrypter.VERSION_KEY_STORE_AES, encrypter.getEncryptionType(ciphertext))
        assertEquals("secret", encrypter.decryptString(ciphertext))
    }

    @Test
    fun missingLegacyVersion4DataKeyThrowsTypedKeyLoss() {
        val encrypter = SecureStringEncrypter(
            ApplicationProvider.getApplicationContext(),
            "version4-missing-data-key"
        )
        val ciphertext = encrypter.encryptString(
            "secret",
            versionOverride = SecureStringEncrypter.VERSION_AES_KEY_ENCRYPTED_PREFERENCE
        )
        val keyReference = JSONObject(ciphertext)
            .getJSONObject("encrypted")
            .getString("key")
        encrypter.encryptedSharedPreference.edit().remove(keyReference).commit()

        try {
            encrypter.decryptString(ciphertext)
            fail("Expected LocalEncryptionKeyLostException")
        } catch (_: LocalEncryptionKeyLostException) {
            // Expected: version 4 remains readable, but lost data keys get the typed recovery signal.
        }
    }
}
