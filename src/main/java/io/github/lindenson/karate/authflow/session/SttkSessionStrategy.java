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
package io.github.lindenson.karate.authflow.session;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.lindenson.karate.authflow.onboarding.OnboardingKeyStore;
import io.github.lindenson.karate.authflow.onboarding.crypto.RgkCryptoCodec;
import io.github.lindenson.karate.authflow.onboarding.crypto.SttkCryptoCodec;
import io.github.lindenson.karate.authflow.spi.AuthRequest;
import io.github.lindenson.karate.authflow.spi.AuthResponse;
import io.github.lindenson.karate.authflow.spi.PostResponseInterceptor;
import io.github.lindenson.karate.authflow.spi.PreRequestInterceptor;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Drives STTK working-flow endpoints (e.g. {@code POST /api/v1/devices/language}) from cleartext
 * features, building the {@code FullGeneralRequest} envelope and decoding the response.
 *
 * <p>Two modes:
 * <ul>
 *   <li><b>skip-encryption</b> ({@code se=true}, the TEST-build path): {@code ed} is base64 of the
 *       cleartext (no AES) and the server skips the request MAC. This is what the TEST-build client
 *       sends and what the server's FULL pipeline validates today.</li>
 *   <li><b>encrypted</b>: full STTK — per-{@code rid} {@code STTK}/{@code STMK} derived from the
 *       onboarding master keys, {@code ed} AES-encrypted, {@code mccd} = STMK MAC; response {@code mcc}
 *       verified and {@code ecd} decrypted. (Requires the server FULL pipeline to read {@code mccd}.)</li>
 * </ul>
 * Either way the master keys / {@code deviceSn} come from the scenario's {@link OnboardingKeyStore}.
 */
public final class SttkSessionStrategy implements PreRequestInterceptor, PostResponseInterceptor {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Function<String, OnboardingKeyStore> keyStores;
    private final int appVersion;
    private final boolean skipEncryption;

    /** scenarioId → {mttkRaw, mtmkRaw}; only used in encrypted mode. */
    private final ConcurrentHashMap<String, byte[][]> masterRaw = new ConcurrentHashMap<>();
    /** scenarioId → {STTK, STMK} for the in-flight request (encrypted mode), or marker for skip mode. */
    private final ConcurrentHashMap<String, byte[][]> pendingSession = new ConcurrentHashMap<>();
    private static final byte[][] SKIP_MARKER = new byte[0][];

    public SttkSessionStrategy(Function<String, OnboardingKeyStore> keyStores, int appVersion, boolean skipEncryption) {
        this.keyStores = Objects.requireNonNull(keyStores, "keyStores");
        this.appVersion = appVersion;
        this.skipEncryption = skipEncryption;
    }

    @Override
    public void intercept(AuthRequest request) {
        OnboardingKeyStore store = keyStores.apply(request.scenarioId());
        if (store == null) {
            throw new OnboardingNotReady();
        }
        store.requireOnboarded(); // ensures deviceSn + master keys exist

        String rid = UUID.randomUUID().toString();
        ObjectNode envelope = MAPPER.createObjectNode();
        envelope.put("rid", utf8(rid));
        envelope.put("v", ByteBuffer.allocate(4).putInt(appVersion).array());
        envelope.put("dsn", utf8(store.deviceSn()));

        byte[] cleartext = utf8(request.bodyAsString());
        if (skipEncryption) {
            envelope.put("se", utf8("true"));
            envelope.put("ed", utf8(Base64.getEncoder().encodeToString(cleartext))); // base64(plaintext), no AES
            // mccd is @NotNull @Size(24) on the envelope; the MAC is skipped under se=true, so a
            // 24-byte placeholder (base64 of 16 zero bytes) satisfies validation.
            envelope.put("mccd", utf8(Base64.getEncoder().encodeToString(new byte[16])));
            pendingSession.put(request.scenarioId(), SKIP_MARKER);
        } else {
            byte[][] master = masterRaw.computeIfAbsent(request.scenarioId(), k -> new byte[][]{
                    SttkCryptoCodec.unwrapMasterKeyUnderRgk(hexDecode(store.mttk()), store.rgk()),
                    SttkCryptoCodec.unwrapMasterKeyUnderRgk(hexDecode(store.mtmk()), store.rgk())
            });
            byte[] sessionId = SttkCryptoCodec.sessionId(rid);
            byte[] sttk = SttkCryptoCodec.deriveSttk(master[0], sessionId);
            byte[] stmk = SttkCryptoCodec.deriveStmk(master[1], sessionId);
            pendingSession.put(request.scenarioId(), new byte[][]{sttk, stmk});

            byte[] ciphertext = RgkCryptoCodec.encryptUnderRgk(cleartext, sttk);
            envelope.put("ed", utf8(Base64.getEncoder().encodeToString(ciphertext)));
            envelope.put("mccd", utf8(SttkCryptoCodec.mac(stmk, ciphertext)));
        }
        request.body(toBytes(envelope));
    }

    @Override
    public void intercept(AuthResponse response) {
        byte[][] session = pendingSession.remove(response.scenarioId());
        if (session == null) {
            return;
        }
        JsonNode envelope = readTree(response.bodyAsString());
        String ecd = envelope.path("ecd").asText(null);
        if (ecd == null) {
            throw new SessionException("STTK response had no 'ecd' (HTTP " + response.status() + "): "
                    + response.bodyAsString());
        }
        byte[] ciphertext = Base64.getDecoder().decode(ecd);

        if (session == SKIP_MARKER) {
            response.body(ciphertext); // se=true: ecd is base64(plaintext); decoded bytes are the cleartext
            return;
        }
        String mcc = envelope.path("mcc").asText(null);
        if (mcc != null && !mcc.isEmpty() && !SttkCryptoCodec.mac(session[1], ciphertext).equals(mcc)) {
            throw new SessionException("STTK response MAC (mcc) mismatch");
        }
        response.body(RgkCryptoCodec.decryptUnderRgk(ciphertext, session[0]));
    }

    private static byte[] utf8(String s) {
        return (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] hexDecode(String hex) {
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private JsonNode readTree(String json) {
        try {
            return MAPPER.readTree(json == null ? "{}" : json);
        } catch (IOException e) {
            throw new SessionException("Could not parse STTK response JSON: " + json);
        }
    }

    private byte[] toBytes(JsonNode node) {
        try {
            return MAPPER.writeValueAsBytes(node);
        } catch (JsonProcessingException e) {
            throw new SessionException("Could not serialize STTK envelope");
        }
    }

    /** Raised when an STTK request is attempted before onboarding produced a key store. */
    public static final class OnboardingNotReady extends SessionException {
        private static final long serialVersionUID = 1L;

        public OnboardingNotReady() {
            super("No onboarding key store for this scenario — onboard before STTK requests");
        }
    }
}
