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

import com.intuit.karate.Results;
import com.intuit.karate.Runner;
import io.github.lindenson.karate.authflow.spi.KarateAuth;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * End-to-end onboarding (ukrsib flavor) against {@link FakeTms}: the Step 0 handshake yields the
 * TMS public key, which the strategy uses to wrap the RGK at Step 1. Hermetic — no network.
 */
@DisplayName("TMS onboarding — ukrsib flavor")
class TmsOnboardingUkrsibTest {

    private static final String FEATURE =
            "classpath:io/github/lindenson/karate/authflow/tms/onboarding-ukrsib.feature";

    @Test
    @DisplayName("5-step onboarding handshakes, decrypts, and issues master keys")
    void onboardsViaHandshake() throws Exception {
        try (FakeTms tms = new FakeTms()) {
            System.setProperty("tms.base", tms.baseUrl());
            try {
                TmsOnboardingConfig config = TmsOnboardingConfig.builder()
                        .flavor(TmsFlavor.UKRSIB)
                        .appVersion(100_000_007)
                        .build();
                TmsOnboardingStrategy strategy = new TmsOnboardingStrategy(config);

                Results results = KarateAuth
                        .register(Runner.path(FEATURE), strategy, strategy)
                        .parallel(1);

                assertEquals(0, results.getFailCount(), results.getErrorMessages());
            } finally {
                System.clearProperty("tms.base");
            }
        }
    }
}
