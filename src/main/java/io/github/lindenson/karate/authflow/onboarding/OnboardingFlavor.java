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

/**
 * crypto backend onboarding flavor.
 *
 * <ul>
 *   <li>{@link #STANDARD} — 4 steps; the device uses a built-in static crypto backend public key + {@code pkr}.</li>
 *   <li>{@link #HANDSHAKE} — 5 steps; Step 0 ({@code /initial_handshake_key}) fetches a per-device crypto backend
 *       public key bound to the device fingerprint.</li>
 * </ul>
 */
public enum OnboardingFlavor {
    STANDARD,
    HANDSHAKE
}
