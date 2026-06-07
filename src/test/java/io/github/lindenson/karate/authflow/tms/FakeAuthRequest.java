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

import io.github.lindenson.karate.authflow.spi.AuthRequest;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/** Minimal in-memory {@link AuthRequest} for unit-testing the strategy without Karate. */
final class FakeAuthRequest implements AuthRequest {

    private final String method;
    private final String url;
    private final String scenarioId;
    private final Map<String, String> headers = new HashMap<>();
    private byte[] body;

    FakeAuthRequest(String method, String url, String scenarioId, String body) {
        this.method = method;
        this.url = url;
        this.scenarioId = scenarioId;
        this.body = body == null ? null : body.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String url() {
        return url;
    }

    @Override
    public String method() {
        return method;
    }

    @Override
    public String header(String name) {
        return headers.get(name);
    }

    @Override
    public void putHeader(String name, String value) {
        headers.put(name, value);
    }

    @Override
    public void removeHeader(String name) {
        headers.remove(name);
    }

    @Override
    public byte[] body() {
        return body;
    }

    @Override
    public void body(byte[] body) {
        this.body = body;
    }

    @Override
    public String bodyAsString() {
        return body == null ? null : new String(body, StandardCharsets.UTF_8);
    }

    @Override
    public String scenarioId() {
        return scenarioId;
    }
}
