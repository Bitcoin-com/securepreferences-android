package com.bitcoin.securepreferences;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;

public class CustomRsaTest {


    private FakeKeyStoreSpi fakeKeyStoreSpi = new FakeKeyStoreSpi();
    private CustomRsa customRsa = new CustomRsa(new FakeKeyStore(
            fakeKeyStoreSpi,
            new FakeProvider("TEST", 1, "INFO"),
            "TEST"));

    @Before
    public void setup() {
        fakeKeyStoreSpi.clear();
    }

    @Test
    public void encryption() {
        String encrypt = customRsa.encrypt("HELLO", "NAMESPACE");
        String decrypt = customRsa.decrypt(encrypt, "NAMESPACE");
        assertThat(decrypt, Matchers.is("HELLO"));

    }
}
