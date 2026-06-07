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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Self-contained in-process crypto backend for the onboarding example: it owns an RSA key pair,
 * unwraps the RGK, decrypts the request payload, and encrypts the response — the inverse of what
 * {@code EncryptedOnboardingStrategy} does — so the example runs end-to-end with no real backend,
 * no network and no Docker.
 */
final class FakeCryptoBackend implements AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final byte[] ZERO_IV = new byte[16];

    /** deviceSn token as the wire carries it: base64 of the SN bytes. */
    static final String DEVICE_SN_TOKEN = Base64.getEncoder().encodeToString("DEMO-DEVICE-1".getBytes(StandardCharsets.UTF_8));
    static final String MTMK = "demo-master-mac-key";
    static final String MTTK = "demo-master-traffic-key";

    private final HttpServer server;
    private final String baseUrl;
    private final KeyPair backend;
    private final Map<String, byte[]> rgkByRid = new ConcurrentHashMap<>();

    FakeCryptoBackend() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        this.backend = kpg.generateKeyPair();
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/api/v1/init/credentials", this::emptyOk);
        server.createContext("/api/v1/init/otp/confirm-otp", this::emptyOk);
        server.createContext("/api/v1/init/access-code/register", this::accessCode);
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

    private void accessCode(HttpExchange ex) throws IOException {
        registrationStep(ex, "{\"mttk\":\"" + MTTK + "\",\"mtmk\":\"" + MTMK + "\"}");
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
