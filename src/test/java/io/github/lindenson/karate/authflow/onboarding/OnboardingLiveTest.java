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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Runs the handshake onboarding against a real crypto backend backend. Skipped unless {@code -Dbackend.base} is set,
 * so it is a no-op in the normal build.
 *
 * <p>Run (nothing secret is stored in the repo — pass it on the command line):
 * <pre>
 * mvn test -Dtest=OnboardingLiveTest \
 *   -Dbackend.base=https://your-backend-host \
 *   -Dbackend.fp=authflow-demo-device \
 *   -Dbackend.login=YOUR_LOGIN -Dbackend.password=YOUR_PASSWORD \
 *   -Dbackend.otp=STUB_OTP -Dbackend.accessCode=9999 \
 *   [-Dbackend.appVersion=100005000] [-Dbackend.rgkBits=128]
 * </pre>
 */
@DisplayName("crypto backend onboarding — live (handshake)")
class OnboardingLiveTest {

    private static final String FEATURE =
            "classpath:io/github/lindenson/karate/authflow/onboarding/onboarding-handshake-live.feature";

    @Test
    @DisplayName("onboards a device against the real crypto backend backend")
    void liveOnboarding() {
        String base = System.getProperty("backend.base");
        Assumptions.assumeTrue(base != null && !base.isBlank(),
                "set -Dbackend.base=... (and backend.fp/login/password/otp/accessCode) to run the live crypto backend onboarding");

        EncryptedOnboardingConfig config = EncryptedOnboardingConfig.builder()
                .flavor(OnboardingFlavor.HANDSHAKE)
                .appVersion(Integer.getInteger("backend.appVersion", 100_005_000))
                .rgkBits(Integer.getInteger("backend.rgkBits", 128))
                .build();
        EncryptedOnboardingStrategy strategy = new EncryptedOnboardingStrategy(config);

        String feature = System.getProperty("backend.feature", FEATURE);
        Results results = KarateAuth
                .register(Runner.path(feature), strategy, strategy)
                .parallel(1);

        assertEquals(0, results.getFailCount(), results.getErrorMessages());
    }
}
