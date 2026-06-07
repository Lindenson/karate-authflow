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

import java.util.Objects;
import java.util.function.Supplier;

/**
 * Immutable per-strategy configuration for {@link EncryptedOnboardingStrategy}.
 *
 * <p>Holds only what the feature cannot express in cleartext: the flavor, the version code/hash
 * sent in the envelope, the RGK size, and — for the {@code standard} flavor — the built-in crypto backend
 * public key (X509 DER) and its {@code pkr}. Business values (credentials, OTP, access code,
 * device info) are written by the {@code .feature} payloads themselves.
 *
 * <p>For {@code handshake} the crypto backend public key and {@code pkr} are obtained at Step 0 instead.
 */
public final class EncryptedOnboardingConfig {

    private final OnboardingFlavor flavor;
    private final int appVersion;
    private final String versionHash;
    private final byte[] builtInServerKey;
    private final String builtInPkr;
    private final int rgkBits;
    private final Supplier<String> otpSupplier;

    private EncryptedOnboardingConfig(Builder b) {
        this.flavor = Objects.requireNonNull(b.flavor, "flavor");
        this.appVersion = b.appVersion;
        this.versionHash = b.versionHash;
        this.builtInServerKey = b.builtInServerKey;
        this.builtInPkr = b.builtInPkr;
        this.rgkBits = b.rgkBits;
        this.otpSupplier = b.otpSupplier;
        if (flavor == OnboardingFlavor.STANDARD && (builtInServerKey == null || builtInPkr == null)) {
            throw new IllegalArgumentException("standard flavor requires builtInServerKey and builtInPkr");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public OnboardingFlavor flavor() {
        return flavor;
    }

    public int appVersion() {
        return appVersion;
    }

    public String versionHash() {
        return versionHash;
    }

    public byte[] builtInServerKey() {
        return builtInServerKey;
    }

    public String builtInPkr() {
        return builtInPkr;
    }

    public int rgkBits() {
        return rgkBits;
    }

    /**
     * @return an OTP supplier that the strategy calls at Step 3 to fill the {@code otp} field, or
     *         {@code null} to use the value written by the feature. Use this for a server that
     *         delivers a real OTP out-of-band (e.g. resolve it interactively from the device/DB).
     */
    public Supplier<String> otpSupplier() {
        return otpSupplier;
    }

    /** Fluent builder for {@link EncryptedOnboardingConfig}. */
    public static final class Builder {
        private OnboardingFlavor flavor = OnboardingFlavor.STANDARD;
        private int appVersion = 1;
        private String versionHash;
        private byte[] builtInServerKey;
        private String builtInPkr;
        private int rgkBits = 128;
        private Supplier<String> otpSupplier;

        public Builder flavor(OnboardingFlavor flavor) {
            this.flavor = flavor;
            return this;
        }

        public Builder appVersion(int appVersion) {
            this.appVersion = appVersion;
            return this;
        }

        public Builder versionHash(String versionHash) {
            this.versionHash = versionHash;
            return this;
        }

        public Builder builtInServerKey(byte[] builtInServerKey) {
            this.builtInServerKey = builtInServerKey;
            return this;
        }

        public Builder builtInPkr(String builtInPkr) {
            this.builtInPkr = builtInPkr;
            return this;
        }

        public Builder rgkBits(int rgkBits) {
            this.rgkBits = rgkBits;
            return this;
        }

        /** Resolve the Step 3 OTP dynamically (overrides whatever the feature wrote). */
        public Builder otpSupplier(Supplier<String> otpSupplier) {
            this.otpSupplier = otpSupplier;
            return this;
        }

        /** Use a fixed Step 3 OTP (e.g. a server-side predictable OTP for a test account). */
        public Builder otp(String constantOtp) {
            this.otpSupplier = () -> constantOtp;
            return this;
        }

        public EncryptedOnboardingConfig build() {
            return new EncryptedOnboardingConfig(this);
        }
    }
}
