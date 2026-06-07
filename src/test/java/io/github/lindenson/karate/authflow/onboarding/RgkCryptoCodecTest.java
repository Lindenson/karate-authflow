/*
 * Copyright 2026 Lindenson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.lindenson.karate.authflow.onboarding;

import io.github.lindenson.karate.authflow.onboarding.crypto.RgkCryptoCodec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Round-trips the codec against decoding written the way the the crypto backend server does it
 * (independent of the codec) — the matryoshka is the #1 bug magnet, so it gets its own oracle.
 */
@DisplayName("RgkCryptoCodec")
class RgkCryptoCodecTest {

    private static final byte[] ZERO_IV = new byte[16];

    /** Server-side: AES/CBC/PKCS5 decrypt with IV=0, mirroring the reference crypto backend. */
    private static byte[] serverAesDecrypt(byte[] ciphertext, byte[] rgk) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rgk, "AES"), new IvParameterSpec(ZERO_IV));
        return c.doFinal(ciphertext);
    }

    /** Server-side: RSA/ECB/PKCS1 unwrap with the crypto backend private key. */
    private static byte[] serverRsaUnwrap(byte[] wrapped, PrivateKey serverPrivate) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, serverPrivate);
        return c.doFinal(wrapped);
    }

    @Test
    @DisplayName("ed: server decode (new String -> b64 decode -> AES decrypt) recovers the JSON")
    void edFieldRoundTrips() throws Exception {
        byte[] rgk = RgkCryptoCodec.generateRgk(128);
        byte[] cleartext = "{\"dfrgprt\":\"fp-1\",\"lag\":\"en-US\"}".getBytes(StandardCharsets.UTF_8);

        byte[] edInner = RgkCryptoCodec.buildEdField(cleartext, rgk); // inner = UTF-8(b64(cipher))

        // Server: new String(ed) is the inner base64; decode it, then AES-decrypt.
        String innerB64 = new String(edInner, StandardCharsets.UTF_8);
        byte[] cipher = Base64.getDecoder().decode(innerB64);
        assertArrayEquals(cleartext, serverAesDecrypt(cipher, rgk));
    }

    @Test
    @DisplayName("rgke: server decode + RSA unwrap recovers the RGK")
    void rgkeFieldRoundTrips() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair backend = kpg.generateKeyPair();
        byte[] serverPubX509 = backend.getPublic().getEncoded();

        byte[] rgk = RgkCryptoCodec.generateRgk(128);
        byte[] rgkeInner = RgkCryptoCodec.buildRgkeField(rgk, serverPubX509);

        String innerB64 = new String(rgkeInner, StandardCharsets.UTF_8);
        byte[] wrapped = Base64.getDecoder().decode(innerB64);
        assertArrayEquals(rgk, serverRsaUnwrap(wrapped, backend.getPrivate()));
    }

    @Test
    @DisplayName("ecd: parseEcdField decrypts the server's single-base64 ciphertext")
    void ecdFieldRoundTrips() throws Exception {
        byte[] rgk = RgkCryptoCodec.generateRgk(128);
        byte[] payload = "{\"deviceSn\":\"AAecho\"}".getBytes(StandardCharsets.UTF_8);

        // Server builds ecd = base64(AES_encrypt(payload)).
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rgk, "AES"), new IvParameterSpec(ZERO_IV));
        String ecd = Base64.getEncoder().encodeToString(c.doFinal(payload));

        assertArrayEquals(payload, RgkCryptoCodec.parseEcdField(ecd, rgk));
    }

    @Test
    @DisplayName("encrypt/decrypt under RGK is a clean round-trip")
    void aesRoundTrips() {
        byte[] rgk = RgkCryptoCodec.generateRgk(128);
        byte[] data = "the quick brown fox".getBytes(StandardCharsets.UTF_8);

        assertArrayEquals(data, RgkCryptoCodec.decryptUnderRgk(RgkCryptoCodec.encryptUnderRgk(data, rgk), rgk));
    }

    @Test
    @DisplayName("generateRgk yields a 128-bit (16-byte) key")
    void rgkIs16Bytes() {
        assertEquals(16, RgkCryptoCodec.generateRgk(128).length);
    }
}
