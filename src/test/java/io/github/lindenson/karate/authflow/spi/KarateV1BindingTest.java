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
package io.github.lindenson.karate.authflow.spi;

import com.intuit.karate.RuntimeHook;
import com.intuit.karate.http.HttpRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("KarateV1Binding seam")
class KarateV1BindingTest {

    private static final byte[] ORIGINAL_BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SEALED_BODY = "{\"sealed\":true}".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("exposes a stable binding id")
    void exposesStableId() {
        assertEquals("karate-1.x", new KarateV1Binding().id());
    }

    @Test
    @DisplayName("createHook produces a Karate RuntimeHook")
    void createHookProducesRuntimeHook() {
        Object hook = new KarateV1Binding().createHook(request -> { });

        assertInstanceOf(RuntimeHook.class, hook);
    }

    @Test
    @DisplayName("createHook rejects a null interceptor")
    void createHookRejectsNull() {
        assertThrows(IllegalArgumentException.class, () -> new KarateV1Binding().createHook(null));
    }

    @Test
    @DisplayName("beforeHttpCall hands the interceptor a mutable request mapped from the native HttpRequest")
    void beforeHttpCallExposesMutableRequest() {
        HttpRequest native_ = new HttpRequest();
        native_.setUrl("https://api.example.com/payments");
        native_.setMethod("POST");
        native_.setBody(ORIGINAL_BODY);

        AtomicReference<AuthRequest> captured = new AtomicReference<>();
        PreRequestInterceptor interceptor = request -> {
            captured.set(request);
            request.putHeader("Authorization", "Bearer test-token");
            request.body(SEALED_BODY);
        };

        RuntimeHook hook = (RuntimeHook) new KarateV1Binding().createHook(interceptor);
        hook.beforeHttpCall(native_, null);

        // The interceptor saw a request reflecting the native one...
        AuthRequest seen = captured.get();
        assertNotNull(seen);
        assertEquals("https://api.example.com/payments", seen.url());
        assertEquals("POST", seen.method());

        // ...and its mutations propagated back to the native HttpRequest before send.
        assertEquals("Bearer test-token", native_.getHeader("Authorization"));
        assertArrayEquals(SEALED_BODY, native_.getBody());
    }
}
