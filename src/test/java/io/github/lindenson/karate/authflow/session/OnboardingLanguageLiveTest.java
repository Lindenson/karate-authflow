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

import com.intuit.karate.Results;
import com.intuit.karate.Runner;
import io.github.lindenson.karate.authflow.onboarding.EncryptedOnboardingConfig;
import io.github.lindenson.karate.authflow.onboarding.OnboardingFlavor;
import io.github.lindenson.karate.authflow.spi.KarateAuth;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Live journey against a real backend: handshake onboarding, then an STTK-protected
 * {@code POST /api/v1/devices/language}. Skipped unless {@code -Dbackend.base} is set.
 *
 * <pre>
 * mvn test -Dtest=OnboardingLanguageLiveTest \
 *   -Dbackend.base=http://HOST:PORT -Dbackend.fp=device-001 \
 *   -Dbackend.login=LOGIN -Dbackend.password=PASSWORD \
 *   -Dbackend.otp=OTP -Dbackend.accessCode=9999
 * </pre>
 */
@DisplayName("Live journey — onboarding + STTK devices/language")
class OnboardingLanguageLiveTest {

    private static final String FEATURE =
            "classpath:io/github/lindenson/karate/authflow/session/onboarding-language-live.feature";

    @Test
    @DisplayName("onboards then changes language under STTK")
    void onboardThenLanguage() {
        String base = System.getProperty("backend.base");
        Assumptions.assumeTrue(base != null && !base.isBlank(),
                "set -Dbackend.base=... (and backend.fp/login/password/otp/accessCode) to run");

        EncryptedOnboardingConfig config = EncryptedOnboardingConfig.builder()
                .flavor(OnboardingFlavor.HANDSHAKE)
                .appVersion(Integer.getInteger("backend.appVersion", 100_005_000))
                .build();
        boolean skipEncryption = !Boolean.getBoolean("backend.encrypt");
        OnboardingSessionFlow flow = new OnboardingSessionFlow(config, skipEncryption);

        Results results = KarateAuth
                .register(Runner.path(FEATURE), flow, flow)
                .parallel(1);

        assertEquals(0, results.getFailCount(), results.getErrorMessages());
    }
}
