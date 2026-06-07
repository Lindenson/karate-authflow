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

import io.github.lindenson.karate.authflow.onboarding.crypto.SttkCryptoCodec;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Proves our pure-JCE STTK/STMK/MAC equal the reference soft-HSM byte-for-byte.
 *
 * <p>Reflection-guarded: the private {@code transenix-crypto} jar is added only by the {@code parity}
 * Maven profile, so this test self-skips in the default build (CI). Run locally with:
 * <pre>mvn test -Pparity -Dtest=SttkCryptoCodecParityTest</pre>
 *
 * <p>LMK constants are the fixed values baked into the reference {@code SoftHsmCryptoService};
 * they exist only to unwrap the reference's {@code *UnderLmk} outputs back to raw keys for comparison.
 */
@DisplayName("STTK parity vs the reference soft-HSM (run with -Pparity)")
class SttkCryptoCodecParityTest {

    private static final String SVC = "ua.com.cartsys.transenix.crypto.impl.SoftHsmCryptoService";
    private static final String CFG = "ua.com.cartsys.transenix.crypto.impl.SoftHsmConfig";

    private static byte[] lmk(int v) {
        byte[] b = new byte[32];
        Arrays.fill(b, (byte) v);
        return b;
    }

    private static final byte[] LMK_MTTK = lmk(0x90);
    private static final byte[] LMK_MTMK = lmk(0xA0);
    private static final byte[] LMK_STTK = lmk(0xB0);
    private static final byte[] LMK_STMK = lmk(0xC0);

    private static void assumeReferenceOnClasspath() {
        try {
            Class.forName(SVC);
        } catch (Throwable t) {
            Assumptions.abort("transenix-crypto not on the classpath — run with -Pparity");
        }
    }

    private static Object referenceService() throws Exception {
        Class<?> cfg = Class.forName(CFG);
        Class<?> svc = Class.forName(SVC);
        return svc.getConstructor(cfg).newInstance(cfg.getDeclaredConstructor().newInstance());
    }

    private static byte[] aes(int mode, byte[] data, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(mode, new SecretKeySpec(key, "AES"));
        return c.doFinal(data);
    }

    private static byte[] refDeriveRaw(Object svc, String method, byte[] sessionId,
                                       byte[] masterUnderLmk, byte[] resultLmk) throws Exception {
        Method m = svc.getClass().getMethod(method, byte[].class, byte[].class);
        Object keyWithKcv = m.invoke(svc, sessionId, masterUnderLmk);
        byte[] underLmk = (byte[]) keyWithKcv.getClass().getMethod("getCryptogram").invoke(keyWithKcv);
        return aes(Cipher.DECRYPT_MODE, underLmk, resultLmk);
    }

    @Test
    @DisplayName("deriveSttk / deriveStmk match the reference")
    void deriveParity() throws Exception {
        assumeReferenceOnClasspath();
        Object svc = referenceService();
        SecureRandom rnd = new SecureRandom();
        byte[] sessionId = new byte[16];
        byte[] mttkRaw = new byte[32];
        byte[] mtmkRaw = new byte[32];
        rnd.nextBytes(sessionId);
        rnd.nextBytes(mttkRaw);
        rnd.nextBytes(mtmkRaw);

        byte[] refSttk = refDeriveRaw(svc, "deriveSttk", sessionId, aes(Cipher.ENCRYPT_MODE, mttkRaw, LMK_MTTK), LMK_STTK);
        byte[] refStmk = refDeriveRaw(svc, "deriveStmk", sessionId, aes(Cipher.ENCRYPT_MODE, mtmkRaw, LMK_MTMK), LMK_STMK);

        assertArrayEquals(refSttk, SttkCryptoCodec.deriveSttk(mttkRaw, sessionId), "STTK mismatch");
        assertArrayEquals(refStmk, SttkCryptoCodec.deriveStmk(mtmkRaw, sessionId), "STMK mismatch");
    }

    @Test
    @DisplayName("128-bit HMAC-SHA256 MAC matches the reference")
    void macParity() throws Exception {
        assumeReferenceOnClasspath();
        Object svc = referenceService();
        byte[] stmkRaw = new byte[32];
        new SecureRandom().nextBytes(stmkRaw);
        byte[] data = "some-ciphertext-bytes-to-mac".getBytes();

        Method m = svc.getClass().getMethod("calculate128bitHmacSha256WithStmk", byte[].class, byte[].class);
        byte[] refMac = (byte[]) m.invoke(svc, data, aes(Cipher.ENCRYPT_MODE, stmkRaw, LMK_STMK));

        assertArrayEquals(refMac, Base64.getDecoder().decode(SttkCryptoCodec.mac(stmkRaw, data)), "MAC mismatch");
    }
}
