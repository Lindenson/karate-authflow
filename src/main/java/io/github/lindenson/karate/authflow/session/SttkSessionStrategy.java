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
 * Drives STTK-protected working-flow endpoints from cleartext features, using the session keys
 * derived from the onboarding master keys.
 *
 * <p>Per request: generate a {@code rid}, derive {@code STTK}/{@code STMK} from the (RGK-unwrapped)
 * master keys and {@code sessionId = Hex(rid)}, encrypt the body into {@code ed}, MAC it into
 * {@code mccd}, and assemble a {@code FullGeneralRequest} envelope. Per response: verify {@code mcc}
 * and decrypt {@code ecd} so the scenario asserts on cleartext.
 *
 * <p>The onboarding result (RGK, master keys, deviceSn) is read from the scenario's
 * {@link OnboardingKeyStore} via the supplied lookup; a request before onboarding fails loudly.
 */
public final class SttkSessionStrategy implements PreRequestInterceptor, PostResponseInterceptor {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Function<String, OnboardingKeyStore> keyStores;
    private final int appVersion;

    /** scenarioId → {mttkRaw, mtmkRaw} (unwrapped once per scenario). */
    private final ConcurrentHashMap<String, byte[][]> masterRaw = new ConcurrentHashMap<>();
    /** scenarioId → {STTK, STMK} for the in-flight request. */
    private final ConcurrentHashMap<String, byte[][]> pendingSession = new ConcurrentHashMap<>();

    public SttkSessionStrategy(Function<String, OnboardingKeyStore> keyStores, int appVersion) {
        this.keyStores = Objects.requireNonNull(keyStores, "keyStores");
        this.appVersion = appVersion;
    }

    @Override
    public void intercept(AuthRequest request) {
        OnboardingKeyStore store = keyStores.apply(request.scenarioId());
        if (store == null) {
            throw new OnboardingNotReady();
        }
        store.requireOnboarded(); // throws OnboardingException.NotOnboarded if not done

        byte[][] master = masterRaw.computeIfAbsent(request.scenarioId(), k -> new byte[][]{
                SttkCryptoCodec.unwrapMasterKeyUnderRgk(hexDecode(store.mttk()), store.rgk()),
                SttkCryptoCodec.unwrapMasterKeyUnderRgk(hexDecode(store.mtmk()), store.rgk())
        });

        String rid = UUID.randomUUID().toString();
        byte[] sessionId = SttkCryptoCodec.sessionId(rid);
        byte[] sttk = SttkCryptoCodec.deriveSttk(master[0], sessionId);
        byte[] stmk = SttkCryptoCodec.deriveStmk(master[1], sessionId);
        pendingSession.put(request.scenarioId(), new byte[][]{sttk, stmk});

        byte[] ciphertext = RgkCryptoCodec.encryptUnderRgk(utf8(request.bodyAsString()), sttk);
        byte[] edInner = utf8(Base64.getEncoder().encodeToString(ciphertext));
        String mac = SttkCryptoCodec.mac(stmk, ciphertext);

        ObjectNode envelope = MAPPER.createObjectNode();
        envelope.put("rid", utf8(rid));
        envelope.put("v", ByteBuffer.allocate(4).putInt(appVersion).array());
        envelope.put("dsn", utf8(store.deviceSn()));
        envelope.put("ed", edInner);
        envelope.put("mccd", utf8(mac));
        request.body(toBytes(envelope));
    }

    @Override
    public void intercept(AuthResponse response) {
        byte[][] session = pendingSession.remove(response.scenarioId());
        if (session == null) {
            return; // a response for a request we did not transform
        }
        JsonNode envelope = readTree(response.bodyAsString());
        String ecd = envelope.path("ecd").asText(null);
        if (ecd == null) {
            throw new SessionException("STTK response had no 'ecd' (HTTP " + response.status() + "): "
                    + response.bodyAsString());
        }
        byte[] ciphertext = Base64.getDecoder().decode(ecd);

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
