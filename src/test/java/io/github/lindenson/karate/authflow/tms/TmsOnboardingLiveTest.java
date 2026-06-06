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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Runs the ukrsib onboarding against a real TMS backend. Skipped unless {@code -Dtms.base} is set,
 * so it is a no-op in the normal build.
 *
 * <p>Run (nothing secret is stored in the repo — pass it on the command line):
 * <pre>
 * mvn test -Dtest=TmsOnboardingLiveTest \
 *   -Dtms.base=https://your-tms-host \
 *   -Dtms.fp=authflow-demo-device \
 *   -Dtms.login=YOUR_LOGIN -Dtms.password=YOUR_PASSWORD \
 *   -Dtms.otp=STUB_OTP -Dtms.accessCode=9999 \
 *   [-Dtms.appVersion=100000007] [-Dtms.rgkBits=128]
 * </pre>
 */
@DisplayName("TMS onboarding — live (ukrsib)")
class TmsOnboardingLiveTest {

    private static final String FEATURE =
            "classpath:io/github/lindenson/karate/authflow/tms/onboarding-ukrsib-live.feature";

    @Test
    @DisplayName("onboards a device against the real TMS backend")
    void liveOnboarding() {
        String base = System.getProperty("tms.base");
        Assumptions.assumeTrue(base != null && !base.isBlank(),
                "set -Dtms.base=... (and tms.fp/login/password/otp/accessCode) to run the live TMS onboarding");

        TmsOnboardingConfig config = TmsOnboardingConfig.builder()
                .flavor(TmsFlavor.UKRSIB)
                .appVersion(Integer.getInteger("tms.appVersion", 100_000_007))
                .rgkBits(Integer.getInteger("tms.rgkBits", 128))
                .build();
        TmsOnboardingStrategy strategy = new TmsOnboardingStrategy(config);

        Results results = KarateAuth
                .register(Runner.path(FEATURE), strategy, strategy)
                .parallel(1);

        assertEquals(0, results.getFailCount(), results.getErrorMessages());
    }
}
