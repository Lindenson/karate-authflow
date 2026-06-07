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
package io.github.lindenson.karate.authflow.onboarding;

import com.intuit.karate.Results;
import com.intuit.karate.Runner;
import io.github.lindenson.karate.authflow.spi.KarateAuth;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * End-to-end onboarding (standard flavor) through the real RGK crypto against {@link FakeCryptoBackend}.
 * The feature is cleartext; the strategy encrypts/decrypts transparently. Hermetic — no network.
 */
@DisplayName("crypto backend onboarding — standard flavor")
class OnboardingStandardTest {

    private static final String FEATURE =
            "classpath:io/github/lindenson/karate/authflow/onboarding/onboarding-standard.feature";

    @Test
    @DisplayName("4-step onboarding decrypts responses and issues master keys")
    void onboardsAndIssuesMasterKeys() throws Exception {
        try (FakeCryptoBackend backend = new FakeCryptoBackend()) {
            System.setProperty("backend.base", backend.baseUrl());
            try {
                EncryptedOnboardingConfig config = EncryptedOnboardingConfig.builder()
                        .flavor(OnboardingFlavor.STANDARD)
                        .appVersion(100_000_007)
                        .builtInServerKey(backend.serverPublicKeyX509())
                        .builtInPkr("STANDARD-PKR")
                        .build();
                EncryptedOnboardingStrategy strategy = new EncryptedOnboardingStrategy(config);

                Results results = KarateAuth
                        .register(Runner.path(FEATURE), strategy, strategy)
                        .parallel(1);

                assertEquals(0, results.getFailCount(), results.getErrorMessages());
            } finally {
                System.clearProperty("backend.base");
            }
        }
    }
}
