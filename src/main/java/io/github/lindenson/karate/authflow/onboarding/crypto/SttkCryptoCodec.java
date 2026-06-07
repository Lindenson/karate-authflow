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
package io.github.lindenson.karate.authflow.onboarding.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Session-layer (STTK) crypto primitives, pure JCE.
 *
 * <p>Derived from the backend soft-HSM: the master keys arrive wrapped under the onboarding RGK
 * ({@code AES/ECB/NoPadding}); session keys are {@code HmacSHA256(masterKey, sessionId)} with
 * {@code sessionId = Hex(rid)}; the MAC is {@code HmacSHA256(STMK, ciphertext)} truncated to 16
 * bytes. STTK payload encryption is the same {@code AES/CBC/PKCS5Padding} (zero IV) used for RGK,
 * so {@link RgkCryptoCodec#encryptUnderRgk}/{@link RgkCryptoCodec#decryptUnderRgk} are reused with
 * the STTK key.
 */
public final class SttkCryptoCodec {

    private SttkCryptoCodec() {
    }

    /**
     * Unwrap a master key delivered wrapped under the onboarding RGK.
     *
     * @param wrappedUnderRgk the master key bytes as {@code AES/ECB/NoPadding(rgk, masterRaw)}
     * @param rgk             the raw onboarding RGK
     * @return the raw master key (e.g. 32 bytes)
     */
    public static byte[] unwrapMasterKeyUnderRgk(byte[] wrappedUnderRgk, byte[] rgk) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rgk, "AES"));
            return c.doFinal(wrappedUnderRgk);
        } catch (GeneralSecurityException e) {
            throw new CryptoCodecException("Could not unwrap master key under RGK", e);
        }
    }

    /** @return the session id: the request id hex-decoded (dashes removed). */
    public static byte[] sessionId(String rid) {
        return hexDecode(rid.replace("-", ""));
    }

    /** STTK = HmacSHA256(mTTK, sessionId) (32 bytes → AES-256 key). */
    public static byte[] deriveSttk(byte[] mttkRaw, byte[] sessionId) {
        return hmacSha256(mttkRaw, sessionId);
    }

    /** STMK = HmacSHA256(mTMK, sessionId). */
    public static byte[] deriveStmk(byte[] mtmkRaw, byte[] sessionId) {
        return hmacSha256(mtmkRaw, sessionId);
    }

    /**
     * The MAC carried in {@code mccd} (request) / {@code mcc} (response):
     * base64 of {@code HmacSHA256(STMK, ciphertext)} truncated to 16 bytes.
     *
     * @param stmk       the session MAC key
     * @param ciphertext the raw ciphertext bytes (base64-decoded {@code ed}/{@code ecd})
     * @return the base64 MAC string
     */
    public static String mac(byte[] stmk, byte[] ciphertext) {
        return Base64.getEncoder().encodeToString(Arrays.copyOf(hmacSha256(stmk, ciphertext), 16));
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new CryptoCodecException("HmacSHA256 failed", e);
        }
    }

    private static byte[] hexDecode(String hex) {
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    /** UTF-8 bytes — exposed so callers building the {@code ed} field share one charset. */
    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
