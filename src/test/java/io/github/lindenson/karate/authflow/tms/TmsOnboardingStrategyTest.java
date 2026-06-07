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

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("TmsOnboardingStrategy routing, ordering and isolation")
class TmsOnboardingStrategyTest {

    private static final String HOST = "http://tms.example.com";

    private static TmsOnboardingStrategy strategy() {
        return new TmsOnboardingStrategy(TmsOnboardingConfig.builder()
                .flavor(TmsFlavor.STANDARD)
                .builtInTmsPublicKey(new byte[]{1, 2, 3})
                .builtInPkr("PKR")
                .build());
    }

    @Test
    @DisplayName("rejects a URL outside the onboarding route table")
    void rejectsOutOfScopeUrl() {
        assertThrows(OnboardingException.OutOfScope.class, () -> strategy()
                .intercept(new FakeAuthRequest("POST", HOST + "/api/v1/init/password/verify", "s1", "{}")));
    }

    @Test
    @DisplayName("rejects a step whose prerequisites are not complete")
    void rejectsOutOfOrderStep() {
        // Step 2 (credentials) before Step 1 (init) on a fresh scenario.
        assertThrows(OnboardingException.OutOfOrder.class, () -> strategy()
                .intercept(new FakeAuthRequest("PUT", HOST + "/api/v1/init/credentials", "s1", "{}")));
    }

    @Test
    @DisplayName("keeps per-scenario state isolated")
    void isolatesPerScenarioState() {
        TmsOnboardingStrategy strategy = strategy();

        strategy.keyStore("scenario-a").rid("RID-A");

        assertNotSame(strategy.keyStore("scenario-a"), strategy.keyStore("scenario-b"));
        assertNull(strategy.keyStore("scenario-b").rid(), "scenario-b must not see scenario-a state");
    }

    @Test
    @DisplayName("resetKeys affects only the target scenario")
    void resetIsScoped() {
        TmsOnboardingStrategy strategy = strategy();
        strategy.keyStore("scenario-a").captureMasterKeys("MTMK", "MTTK");
        strategy.keyStore("scenario-b").captureMasterKeys("MTMK", "MTTK");

        strategy.resetKeys("scenario-a");

        assertThrows(OnboardingException.NotOnboarded.class,
                () -> strategy.keyStore("scenario-a").requireOnboarded());
        // scenario-b is untouched
        strategy.keyStore("scenario-b").requireOnboarded();
    }
}
