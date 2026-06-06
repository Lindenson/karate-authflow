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
package io.github.lindenson.karate.authflow.tms;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.lindenson.karate.authflow.spi.AuthRequest;
import io.github.lindenson.karate.authflow.spi.AuthResponse;
import io.github.lindenson.karate.authflow.spi.PostResponseInterceptor;
import io.github.lindenson.karate.authflow.spi.PreRequestInterceptor;
import io.github.lindenson.karate.authflow.tms.crypto.TmsCryptoCodec;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Drives the Transenix TMS device-onboarding flow from cleartext Karate features.
 *
 * <p>Register as both interceptors:
 * <pre>{@code
 * TmsOnboardingStrategy s = new TmsOnboardingStrategy(config);
 * KarateAuth.register(Runner.path("classpath:features"), s, s).parallel(n);
 * }</pre>
 *
 * <p>The feature writes the cleartext per-step payloads (§6 of the handover) and asserts on the
 * decrypted responses; this strategy owns RGK generation, RSA wrap, AES-CBC, the base64
 * matryoshka, envelope assembly, sticky {@code rid}, {@code dsn} bookkeeping, step ordering, and
 * capture of {@code mTMK}/{@code mTTK}. State is isolated per scenario via {@code scenarioId()}.
 */
public final class TmsOnboardingStrategy implements PreRequestInterceptor, PostResponseInterceptor {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final List<OnboardStep> UKRSIB_SEQUENCE =
            List.of(OnboardStep.HANDSHAKE, OnboardStep.INIT, OnboardStep.CREDENTIALS, OnboardStep.OTP, OnboardStep.ACCESS_CODE);
    private static final List<OnboardStep> STANDARD_SEQUENCE =
            List.of(OnboardStep.INIT, OnboardStep.CREDENTIALS, OnboardStep.OTP, OnboardStep.ACCESS_CODE);

    private static final Map<RequestKey, OnboardStep> ROUTES = Map.of(
            new RequestKey("POST", "/api/v1/init/initial_handshake_key"), OnboardStep.HANDSHAKE,
            new RequestKey("POST", "/api/v1/init"), OnboardStep.INIT,
            new RequestKey("PUT", "/api/v1/init/credentials"), OnboardStep.CREDENTIALS,
            new RequestKey("PUT", "/api/v1/init/otp/confirm-otp"), OnboardStep.OTP,
            new RequestKey("PUT", "/api/v1/init/access-code/register"), OnboardStep.ACCESS_CODE);

    /** Inner cleartext fields that are {@code byte[]} server-side: base64(UTF-8)-encode from plain. */
    private static final Map<OnboardStep, List<String>> ENCODE_FIELDS = Map.of(
            OnboardStep.INIT, List.of("fbrid", "dad/dn", "dad/did", "dad/sen", "dad/osv", "dad/imi", "dad/iso"),
            OnboardStep.CREDENTIALS, List.of("ussLg", "urrPsa"));

    private final TmsOnboardingConfig config;
    private final ConcurrentHashMap<String, TmsKeyStore> stores = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, OnboardStep> pending = new ConcurrentHashMap<>();

    public TmsOnboardingStrategy(TmsOnboardingConfig config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    /** The per-scenario key store (created on first use). */
    public TmsKeyStore keyStore(String scenarioId) {
        return stores.computeIfAbsent(scenarioId, k -> new TmsKeyStore());
    }

    /** Wipe a scenario's onboarding state so it can re-onboard from scratch. */
    public void resetKeys(String scenarioId) {
        TmsKeyStore store = stores.get(scenarioId);
        if (store != null) {
            store.resetKeys();
        }
    }

    // ------------------------------------------------------------------ request

    @Override
    public void intercept(AuthRequest request) {
        OnboardStep step = route(request.method(), pathOf(request.url()));
        TmsKeyStore store = keyStore(request.scenarioId());
        checkOrder(step, store);
        pending.put(request.scenarioId(), step);

        switch (step) {
            case HANDSHAKE -> rememberFingerprint(request, store); // plain body, left as-is
            case INIT -> buildInit(request, store);
            default -> buildRegistration(request, store);
        }
    }

    private void rememberFingerprint(AuthRequest request, TmsKeyStore store) {
        JsonNode body = readTree(request.bodyAsString());
        store.pkr(body.path("dfrgprt").asText(null)); // ukrsib: pkr == deviceFingerprint
    }

    private void buildInit(AuthRequest request, TmsKeyStore store) {
        ObjectNode cleartext = (ObjectNode) readTree(request.bodyAsString());
        if (store.rid() == null) {
            store.rid(UUID.randomUUID().toString());
            store.rgk(TmsCryptoCodec.generateRgk(config.rgkBits()));
        }
        resolveTmsKey(cleartext, store);
        encodeInnerFields(cleartext, OnboardStep.INIT);

        ObjectNode envelope = baseEnvelope(store);
        envelope.put("pkr", store.pkr().getBytes(StandardCharsets.UTF_8));
        envelope.put("rgke", TmsCryptoCodec.buildRgkeField(store.rgk(), store.tmsPublicKey()));
        envelope.put("ed", TmsCryptoCodec.buildEdField(toBytes(cleartext), store.rgk()));
        request.body(toBytes(envelope));
    }

    private void resolveTmsKey(ObjectNode initCleartext, TmsKeyStore store) {
        if (config.flavor() == TmsFlavor.STANDARD) {
            store.tmsPublicKey(config.builtInTmsPublicKey());
            store.pkr(config.builtInPkr());
        } else if (store.tmsPublicKey() == null) {
            throw new OnboardingException.OutOfOrder(OnboardStep.INIT,
                    "ukrsib Step 1 requires Step 0 handshake first (no TMS public key captured)");
        } else if (store.pkr() == null) {
            store.pkr(initCleartext.path("dfrgprt").asText(null));
        }
    }

    private void buildRegistration(AuthRequest request, TmsKeyStore store) {
        OnboardStep step = pending.get(request.scenarioId());
        ObjectNode cleartext = (ObjectNode) readTree(request.bodyAsString());
        encodeInnerFields(cleartext, step);

        ObjectNode envelope = baseEnvelope(store);
        envelope.put("dsn", store.deviceSn().getBytes(StandardCharsets.UTF_8));
        envelope.put("ed", TmsCryptoCodec.buildEdField(toBytes(cleartext), store.rgk()));
        request.body(toBytes(envelope));
    }

    /** rid + v (+ optional rhssh); os/se omitted. byte[] values are base64'd by Jackson. */
    private ObjectNode baseEnvelope(TmsKeyStore store) {
        ObjectNode envelope = MAPPER.createObjectNode();
        envelope.put("rid", store.rid().getBytes(StandardCharsets.UTF_8));
        envelope.put("v", ByteBuffer.allocate(4).putInt(config.appVersion()).array());
        if (config.versionHash() != null) {
            envelope.put("rhssh", config.versionHash().getBytes(StandardCharsets.UTF_8));
        }
        return envelope;
    }

    // ------------------------------------------------------------------ response

    @Override
    public void intercept(AuthResponse response) {
        OnboardStep step = pending.remove(response.scenarioId());
        if (step == null) {
            return; // a response for a request we did not transform
        }
        TmsKeyStore store = keyStore(response.scenarioId());

        if (step == OnboardStep.HANDSHAKE) {
            JsonNode body = readTree(response.bodyAsString());
            String ihshky = body.path("ihshky").asText(null);
            if (ihshky == null) {
                throw new OnboardingException("Step 0 response had no 'ihshky'");
            }
            store.tmsPublicKey(java.util.Base64.getDecoder().decode(ihshky));
            store.markCompleted(step);
            return;
        }

        JsonNode envelope = readTree(response.bodyAsString());
        String ecd = envelope.path("ecd").asText(null);
        if (ecd == null) {
            throw new OnboardingException("Encrypted response had no 'ecd' for step " + step);
        }
        // mcc is absent on onboarding (RGK != STTK); nothing to verify.
        byte[] cleartext = TmsCryptoCodec.parseEcdField(ecd, store.rgk());
        response.body(cleartext); // hand the scenario plaintext

        JsonNode payload = readTree(new String(cleartext, StandardCharsets.UTF_8));
        if (step == OnboardStep.INIT) {
            store.deviceSn(payload.path("deviceSn").asText(null));
        } else if (step == OnboardStep.ACCESS_CODE) {
            store.captureMasterKeys(payload.path("mtmk").asText(null), payload.path("mttk").asText(null));
        }
        store.markCompleted(step);
    }

    // ------------------------------------------------------------------ helpers

    private OnboardStep route(String method, String path) {
        OnboardStep step = ROUTES.get(new RequestKey(method.toUpperCase(), path));
        if (step == null) {
            throw new OnboardingException.OutOfScope(method, path);
        }
        return step;
    }

    private void checkOrder(OnboardStep step, TmsKeyStore store) {
        List<OnboardStep> sequence = config.flavor() == TmsFlavor.UKRSIB ? UKRSIB_SEQUENCE : STANDARD_SEQUENCE;
        int index = sequence.indexOf(step);
        if (index < 0) {
            throw new OnboardingException.OutOfOrder(step, "not part of the " + config.flavor() + " sequence");
        }
        for (int i = 0; i < index; i++) {
            if (!store.isCompleted(sequence.get(i))) {
                throw new OnboardingException.OutOfOrder(step, "missing prerequisite " + sequence.get(i));
            }
        }
    }

    private void encodeInnerFields(ObjectNode cleartext, OnboardStep step) {
        for (String path : ENCODE_FIELDS.getOrDefault(step, List.of())) {
            String[] parts = path.split("/");
            ObjectNode node = cleartext;
            boolean reachable = true;
            for (int i = 0; i < parts.length - 1 && reachable; i++) {
                JsonNode child = node.get(parts[i]);
                if (child instanceof ObjectNode objectChild) {
                    node = objectChild;
                } else {
                    reachable = false;
                }
            }
            String leaf = parts[parts.length - 1];
            JsonNode value = reachable ? node.get(leaf) : null;
            if (value != null && value.isTextual()) {
                String encoded = java.util.Base64.getEncoder()
                        .encodeToString(value.asText().getBytes(StandardCharsets.UTF_8));
                node.put(leaf, encoded);
            }
        }
    }

    private static String pathOf(String url) {
        try {
            return URI.create(url).getPath();
        } catch (RuntimeException e) {
            return url;
        }
    }

    private JsonNode readTree(String json) {
        try {
            return MAPPER.readTree(json == null ? "{}" : json);
        } catch (IOException e) {
            throw new OnboardingException("Could not parse JSON: " + json, e);
        }
    }

    private byte[] toBytes(JsonNode node) {
        try {
            return MAPPER.writeValueAsBytes(node);
        } catch (JsonProcessingException e) {
            throw new OnboardingException("Could not serialize JSON", e);
        }
    }

    /** Method + path identifying an onboarding endpoint. */
    private record RequestKey(String method, String path) {
    }
}
