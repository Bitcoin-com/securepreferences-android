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
}