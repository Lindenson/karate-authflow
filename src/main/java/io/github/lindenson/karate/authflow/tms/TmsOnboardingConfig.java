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

import java.util.Objects;

/**
 * Immutable per-strategy configuration for {@link TmsOnboardingStrategy}.
 *
 * <p>Holds only what the feature cannot express in cleartext: the flavor, the version code/hash
 * sent in the envelope, the RGK size, and — for the {@code standard} flavor — the built-in TMS
 * public key (X509 DER) and its {@code pkr}. Business values (credentials, OTP, access code,
 * device info) are written by the {@code .feature} payloads themselves.
 *
 * <p>For {@code ukrsib} the TMS public key and {@code pkr} are obtained at Step 0 instead.
 */
public final class TmsOnboardingConfig {

    private final TmsFlavor flavor;
    private final int appVersion;
    private final String versionHash;
    private final byte[] builtInTmsPublicKey;
    private final String builtInPkr;
    private final int rgkBits;

    private TmsOnboardingConfig(Builder b) {
        this.flavor = Objects.requireNonNull(b.flavor, "flavor");
        this.appVersion = b.appVersion;
        this.versionHash = b.versionHash;
        this.builtInTmsPublicKey = b.builtInTmsPublicKey;
        this.builtInPkr = b.builtInPkr;
        this.rgkBits = b.rgkBits;
        if (flavor == TmsFlavor.STANDARD && (builtInTmsPublicKey == null || builtInPkr == null)) {
            throw new IllegalArgumentException("standard flavor requires builtInTmsPublicKey and builtInPkr");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public TmsFlavor flavor() {
        return flavor;
    }

    public int appVersion() {
        return appVersion;
    }

    public String versionHash() {
        return versionHash;
    }

    public byte[] builtInTmsPublicKey() {
        return builtInTmsPublicKey;
    }

    public String builtInPkr() {
        return builtInPkr;
    }

    public int rgkBits() {
        return rgkBits;
    }

    /** Fluent builder for {@link TmsOnboardingConfig}. */
    public static final class Builder {
        private TmsFlavor flavor = TmsFlavor.STANDARD;
        private int appVersion = 1;
        private String versionHash;
        private byte[] builtInTmsPublicKey;
        private String builtInPkr;
        private int rgkBits = 128;

        public Builder flavor(TmsFlavor flavor) {
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

        public Builder builtInTmsPublicKey(byte[] builtInTmsPublicKey) {
            this.builtInTmsPublicKey = builtInTmsPublicKey;
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

        public TmsOnboardingConfig build() {
            return new TmsOnboardingConfig(this);
        }
    }
}
