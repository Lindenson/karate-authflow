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

/** Base type for crypto backend onboarding strategy failures (surfaced as scenario failures). */
public class OnboardingException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public OnboardingException(String message) {
        super(message);
    }

    public OnboardingException(String message, Throwable cause) {
        super(message, cause);
    }

    /** A URL outside the onboarding route table was driven through the strategy. */
    public static final class OutOfScope extends OnboardingException {
        private static final long serialVersionUID = 1L;

        public OutOfScope(String method, String path) {
            super("Out-of-scope onboarding request: " + method + " " + path
                    + " is not one of the onboarding endpoints");
        }
    }

    /** A step was driven before its prerequisite steps had completed. */
    public static final class OutOfOrder extends OnboardingException {
        private static final long serialVersionUID = 1L;

        public OutOfOrder(OnboardStep step, String detail) {
            super("Onboarding step " + step + " attempted out of order: " + detail);
        }
    }

    /** Onboarding result was required before Step 4 completed. */
    public static final class NotOnboarded extends OnboardingException {
        private static final long serialVersionUID = 1L;

        public NotOnboarded() {
            super("Onboarding is not complete: master keys (mTMK/mTTK) are not available yet");
        }
    }
}
