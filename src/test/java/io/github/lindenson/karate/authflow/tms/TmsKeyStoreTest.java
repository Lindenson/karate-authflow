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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("TmsKeyStore")
class TmsKeyStoreTest {

    @Test
    @DisplayName("requireOnboarded fails before Step 4 completes")
    void requireBeforeOnboardedFails() {
        assertThrows(OnboardingException.NotOnboarded.class, () -> new TmsKeyStore().requireOnboarded());
    }

    @Test
    @DisplayName("captureMasterKeys exposes the onboarding result")
    void capturesMasterKeys() {
        TmsKeyStore store = new TmsKeyStore();
        store.rid("rid-1");
        store.deviceSn("dsn-token");
        store.captureMasterKeys("MTMK-1", "MTTK-1");

        assertEquals(TmsKeyStore.Status.ONBOARDED, store.status());
        TmsKeyStore.Onboarded onboarded = store.requireOnboarded();
        assertEquals("MTMK-1", onboarded.mtmk());
        assertEquals("MTTK-1", onboarded.mttk());
        assertEquals("dsn-token", onboarded.deviceSn());
        assertEquals("rid-1", onboarded.rid());
    }

    @Test
    @DisplayName("resetKeys clears state and completed steps")
    void resetClearsState() {
        TmsKeyStore store = new TmsKeyStore();
        store.markCompleted(OnboardStep.INIT);
        store.captureMasterKeys("MTMK-1", "MTTK-1");

        store.resetKeys();

        assertEquals(TmsKeyStore.Status.NEW, store.status());
        assertFalse(store.isCompleted(OnboardStep.INIT));
        assertThrows(OnboardingException.NotOnboarded.class, store::requireOnboarded);
    }
}
