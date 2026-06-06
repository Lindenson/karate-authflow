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
package io.github.lindenson.karate.authflow.tms.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Plain-JCE crypto primitives for the TMS onboarding (RGK) flow, plus the wire
 * base64 "matryoshka" helpers.
 *
 * <p>All parameters are fixed by the server (verified against {@code softpos-core}):
 * <ul>
 *   <li>RGK payloads: {@code AES/CBC/PKCS5Padding}, IV = 16 zero bytes, key = the raw RGK.</li>
 *   <li>RGK wrap: {@code RSA/ECB/PKCS1Padding} under the TMS public key (X509 DER).</li>
 * </ul>
 *
 * <p>Matryoshka: a request {@code byte[]} crypto field is <b>double</b> base64 on the
 * wire — the inner base64 (this codec) plus the outer base64 Jackson adds to a {@code byte[]}.
 * This codec produces the <b>inner</b> form (a base64 string's UTF-8 bytes) for {@code ed}/{@code rgke};
 * a response {@code ecd} is <b>single</b> base64 of the ciphertext.
 */
public final class TmsCryptoCodec {

    /** Fixed all-zero IV used by both encrypt and decrypt paths on the server. */
    private static final byte[] ZERO_IV = new byte[16];

    private TmsCryptoCodec() {
    }

    /**
     * Generate a fresh AES RGK (client-side, once per scenario before Step 1).
     *
     * @param bits key size in bits (128 by default for legacy clients)
     * @return raw RGK key bytes
     */
    public static byte[] generateRgk(int bits) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(bits);
            return kg.generateKey().getEncoded();
        } catch (GeneralSecurityException e) {
            throw new TmsCryptoException("Could not generate RGK", e);
        }
    }

    /**
     * Wrap the RGK under the TMS public key ({@code RSA/ECB/PKCS1Padding}).
     *
     * @param rgk                 raw RGK bytes
     * @param tmsPublicKeyX509Der TMS public key, X509-encoded DER
     * @return the RSA-wrapped RGK bytes (binary, before any base64)
     */
    public static byte[] wrapRgk(byte[] rgk, byte[] tmsPublicKeyX509Der) {
        try {
            PublicKey tmsPub = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(tmsPublicKeyX509Der));
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, tmsPub);
            return rsa.doFinal(rgk);
        } catch (GeneralSecurityException e) {
            throw new TmsCryptoException("Could not wrap RGK under the TMS public key", e);
        }
    }

    /**
     * Encrypt cleartext under the RGK ({@code AES/CBC/PKCS5Padding}, IV = 16 zero bytes).
     *
     * @param cleartext plaintext bytes
     * @param rgk       raw RGK key bytes
     * @return ciphertext bytes (binary, before any base64)
     */
    public static byte[] encryptUnderRgk(byte[] cleartext, byte[] rgk) {
        return aes(Cipher.ENCRYPT_MODE, cleartext, rgk);
    }

    /**
     * Decrypt ciphertext under the RGK.
     *
     * @param ciphertext ciphertext bytes (already base64-decoded)
     * @param rgk        raw RGK key bytes
     * @return plaintext bytes
     */
    public static byte[] decryptUnderRgk(byte[] ciphertext, byte[] rgk) {
        return aes(Cipher.DECRYPT_MODE, ciphertext, rgk);
    }

    private static byte[] aes(int mode, byte[] input, byte[] rgk) {
        try {
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aes.init(mode, new SecretKeySpec(rgk, "AES"), new IvParameterSpec(ZERO_IV));
            return aes.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new TmsCryptoException("RGK AES operation failed", e);
        }
    }

    /**
     * Build the inner wire value for the request {@code ed} field: the UTF-8 bytes of
     * {@code base64(AES_RGK(cleartextJson))}. Jackson adds the outer base64 when it
     * serialises the {@code byte[]} envelope field.
     *
     * @param cleartextJson the per-step cleartext JSON bytes
     * @param rgk           raw RGK key bytes
     * @return the inner {@code byte[]} to assign to the envelope's {@code ed}
     */
    public static byte[] buildEdField(byte[] cleartextJson, byte[] rgk) {
        return innerB64Bytes(encryptUnderRgk(cleartextJson, rgk));
    }

    /**
     * Build the inner wire value for the request {@code rgke} field: the UTF-8 bytes of
     * {@code base64(RSA_wrap(rgk))}.
     *
     * @param rgk                 raw RGK key bytes
     * @param tmsPublicKeyX509Der TMS public key, X509 DER
     * @return the inner {@code byte[]} to assign to the envelope's {@code rgke}
     */
    public static byte[] buildRgkeField(byte[] rgk, byte[] tmsPublicKeyX509Der) {
        return innerB64Bytes(wrapRgk(rgk, tmsPublicKeyX509Der));
    }

    /**
     * Parse a response {@code ecd} field (single base64 of ciphertext) back into cleartext.
     *
     * @param ecd the {@code ecd} string from the response envelope
     * @param rgk raw RGK key bytes
     * @return the decrypted cleartext bytes
     */
    public static byte[] parseEcdField(String ecd, byte[] rgk) {
        return decryptUnderRgk(Base64.getDecoder().decode(ecd), rgk);
    }

    private static byte[] innerB64Bytes(byte[] binary) {
        return Base64.getEncoder().encodeToString(binary).getBytes(StandardCharsets.UTF_8);
    }
}
