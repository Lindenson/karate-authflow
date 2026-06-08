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
package io.github.lindenson.karate.authflow.examples;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.lindenson.karate.authflow.onboarding.crypto.RgkCryptoCodec;
import io.github.lindenson.karate.authflow.onboarding.crypto.SttkCryptoCodec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Self-contained in-process crypto backend for the onboarding example. It mirrors the real server
 * for both layers, so the example runs end-to-end with no real backend, no network and no Docker:
 *
 * <ul>
 *   <li><b>Onboarding (RGK):</b> owns an RSA key pair, unwraps the RGK, decrypts each request
 *       payload and encrypts each response — the inverse of {@code EncryptedOnboardingStrategy}.
 *       At access-code it issues the master keys ({@code mTTK}/{@code mTMK}) <b>wrapped under the
 *       RGK and hex-encoded</b>, exactly as the device expects.</li>
 *   <li><b>Session (STTK):</b> serves {@code POST /api/v1/devices/language} — re-derives the same
 *       per-request {@code STTK}/{@code STMK} from the issued master keys and the request {@code rid},
 *       verifies the request MAC ({@code mccd}), decrypts {@code ed}, then returns an encrypted,
 *       MAC'd response ({@code ecd}/{@code mcc}) — the inverse of {@code SttkSessionStrategy}.</li>
 * </ul>
 */
final class FakeCryptoBackend implements AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final byte[] ZERO_IV = new byte[16];
    private static final SecureRandom RNG = new SecureRandom();

    /** deviceSn token as the wire carries it: base64 of the SN bytes. */
    static final String DEVICE_SN_TOKEN = Base64.getEncoder().encodeToString("DEMO-DEVICE-1".getBytes(StandardCharsets.UTF_8));

    private final HttpServer server;
    private final String baseUrl;
    private final KeyPair backend;
    private final Map<String, byte[]> rgkByRid = new ConcurrentHashMap<>();

    /** Raw master keys issued at access-code; reused to derive the session keys for working flows. */
    private volatile byte[] masterTtkRaw;
    private volatile byte[] masterTmkRaw;

    FakeCryptoBackend() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        this.backend = kpg.generateKeyPair();
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/api/v1/init/initial_handshake_key", this::handshake);
        server.createContext("/api/v1/init/credentials", this::emptyOk);
        server.createContext("/api/v1/init/otp/confirm-otp", this::emptyOk);
        server.createContext("/api/v1/init/access-code/register", this::accessCode);
        server.createContext("/api/v1/devices/language", this::language);
        server.createContext("/api/v1/init", this::init);
        server.setExecutor(null);
        server.start();
    }

    String baseUrl() {
        return baseUrl;
    }

    /** The backend public key (X509 DER) — configured as the STANDARD-flavor built-in key. */
    byte[] serverPublicKeyX509() {
        return backend.getPublic().getEncoded();
    }

    // ------------------------------------------------------------------ onboarding (RGK)

    /**
     * HANDSHAKE Step 0: hand the device our public key (base64 X.509 DER) as {@code ihshky}. The
     * device captures it and uses it to RSA-wrap the RGK at Step 1 (no built-in key needed).
     */
    private void handshake(HttpExchange ex) throws IOException {
        respond(ex, 200, "{\"ihshky\":\"" + Base64.getEncoder().encodeToString(serverPublicKeyX509()) + "\"}");
    }

    private void init(HttpExchange ex) throws IOException {
        try {
            JsonNode env = MAPPER.readTree(readBody(ex));
            String rid = dtoString(env.path("rid").asText());
            byte[] rgk = rsaUnwrap(innerBinary(env.path("rgke").asText()));
            rgkByRid.put(rid, rgk);
            decryptEd(env, rgk);
            respondEnvelope(ex, rid, encryptEcd("{\"deviceSn\":\"" + DEVICE_SN_TOKEN + "\"}", rgk));
        } catch (Exception e) {
            respond(ex, 500, "{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    private void emptyOk(HttpExchange ex) throws IOException {
        registrationStep(ex, "{}");
    }

    /** Step 4: issue the master keys wrapped under the RGK (hex), as the real backend does. */
    private void accessCode(HttpExchange ex) throws IOException {
        try {
            JsonNode env = MAPPER.readTree(readBody(ex));
            String rid = dtoString(env.path("rid").asText());
            byte[] rgk = rgkByRid.get(rid);
            if (rgk == null) {
                respond(ex, 400, "{\"error\":\"unknown rid\"}");
                return;
            }
            decryptEd(env, rgk);
            masterTtkRaw = randomKey();
            masterTmkRaw = randomKey();
            String payload = "{\"mttk\":\"" + hex(wrapUnderRgk(masterTtkRaw, rgk)) + "\","
                    + "\"mtmk\":\"" + hex(wrapUnderRgk(masterTmkRaw, rgk)) + "\"}";
            respondEnvelope(ex, rid, encryptEcd(payload, rgk));
        } catch (Exception e) {
            respond(ex, 500, "{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    private void registrationStep(HttpExchange ex, String payload) throws IOException {
        try {
            JsonNode env = MAPPER.readTree(readBody(ex));
            byte[] rgk = rgkByRid.get(dtoString(env.path("rid").asText()));
            if (rgk == null) {
                respond(ex, 400, "{\"error\":\"unknown rid\"}");
                return;
            }
            decryptEd(env, rgk);
            respondEnvelope(ex, dtoString(env.path("rid").asText()), encryptEcd(payload, rgk));
        } catch (Exception e) {
            respond(ex, 500, "{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    // ------------------------------------------------------------------ session (STTK)

    /**
     * {@code POST /api/v1/devices/language} under the per-request session key. Re-derives
     * {@code STTK}/{@code STMK} from the issued master keys and {@code rid}, verifies the request
     * MAC, decrypts the body, and returns an encrypted + MAC'd response.
     */
    private void language(HttpExchange ex) throws IOException {
        try {
            JsonNode env = MAPPER.readTree(readBody(ex));
            String rid = dtoString(env.path("rid").asText());
            byte[] sessionId = SttkCryptoCodec.sessionId(rid);
            byte[] sttk = SttkCryptoCodec.deriveSttk(masterTtkRaw, sessionId);
            byte[] stmk = SttkCryptoCodec.deriveStmk(masterTmkRaw, sessionId);

            byte[] ciphertext = innerBinary(env.path("ed").asText());
            String mccd = dtoString(env.path("mccd").asText());
            if (!SttkCryptoCodec.mac(stmk, ciphertext).equals(mccd)) {
                respond(ex, 500, "{\"errorCode\":\"3307\",\"errorText\":\"Cryptography error\"}");
                return;
            }
            // request body (e.g. {"language":"en"}) decrypts cleanly — accepted.
            RgkCryptoCodec.decryptUnderRgk(ciphertext, sttk);

            byte[] respCipher = RgkCryptoCodec.encryptUnderRgk("{}".getBytes(StandardCharsets.UTF_8), sttk);
            String ecd = Base64.getEncoder().encodeToString(respCipher);
            String mcc = SttkCryptoCodec.mac(stmk, respCipher);
            respond(ex, 200, "{\"reid\":\"" + rid + "\",\"ecd\":\"" + ecd + "\",\"mcc\":\"" + mcc + "\"}");
        } catch (Exception e) {
            respond(ex, 500, "{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    // ------------------------------------------------------------------ crypto helpers

    private static String dtoString(String wireValue) {
        return new String(Base64.getDecoder().decode(wireValue), StandardCharsets.UTF_8);
    }

    private static byte[] innerBinary(String wireValue) {
        return Base64.getDecoder().decode(new String(Base64.getDecoder().decode(wireValue), StandardCharsets.UTF_8));
    }

    private byte[] decryptEd(JsonNode env, byte[] rgk) throws Exception {
        return aes(Cipher.DECRYPT_MODE, innerBinary(env.path("ed").asText()), rgk);
    }

    private String encryptEcd(String payload, byte[] rgk) throws Exception {
        return Base64.getEncoder().encodeToString(aes(Cipher.ENCRYPT_MODE, payload.getBytes(StandardCharsets.UTF_8), rgk));
    }

    private byte[] rsaUnwrap(byte[] wrapped) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, backend.getPrivate());
        return c.doFinal(wrapped);
    }

    private static byte[] aes(int mode, byte[] data, byte[] rgk) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(mode, new SecretKeySpec(rgk, "AES"), new IvParameterSpec(ZERO_IV));
        return c.doFinal(data);
    }

    /** Wrap a raw master key under the RGK ({@code AES/ECB/NoPadding}) — the delivery form. */
    private static byte[] wrapUnderRgk(byte[] masterRaw, byte[] rgk) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rgk, "AES"));
        return c.doFinal(masterRaw);
    }

    private static byte[] randomKey() {
        byte[] k = new byte[32]; // 32 bytes → AES-256 session key
        RNG.nextBytes(k);
        return k;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private void respondEnvelope(HttpExchange ex, String reid, String ecd) throws IOException {
        respond(ex, 200, "{\"reid\":\"" + reid + "\",\"ecd\":\"" + ecd + "\"}");
    }

    private static String readBody(HttpExchange ex) throws IOException {
        return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static void respond(HttpExchange ex, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
