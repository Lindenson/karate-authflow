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

import java.util.EnumSet;

/**
 * Per-scenario onboarding crypto state. Mutated only by the strategy's step handlers, which run
 * sequentially within a scenario, so this type itself need not be thread-safe — cross-scenario
 * isolation is provided by the strategy keying one store per {@code scenarioId()}.
 */
public final class OnboardingKeyStore {

    /** Onboarding lifecycle status. */
    public enum Status { NEW, ONBOARDED }

    /** Immutable view of a completed onboarding, for follow-up flows. */
    public static final class Onboarded {
        private final String deviceSn;
        private final String rid;
        private final String mtmk;
        private final String mttk;

        Onboarded(String deviceSn, String rid, String mtmk, String mttk) {
            this.deviceSn = deviceSn;
            this.rid = rid;
            this.mtmk = mtmk;
            this.mttk = mttk;
        }

        public String deviceSn() {
            return deviceSn;
        }

        public String rid() {
            return rid;
        }

        public String mtmk() {
            return mtmk;
        }

        public String mttk() {
            return mttk;
        }
    }

    private final EnumSet<OnboardStep> completed = EnumSet.noneOf(OnboardStep.class);

    private byte[] serverPublicKey;
    private String pkr;
    private byte[] rgk;
    private String rid;
    private String deviceSn;
    private String mtmk;
    private String mttk;
    private Status status = Status.NEW;

    public EnumSet<OnboardStep> completed() {
        return completed;
    }

    public boolean isCompleted(OnboardStep step) {
        return completed.contains(step);
    }

    public void markCompleted(OnboardStep step) {
        completed.add(step);
    }

    public byte[] serverPublicKey() {
        return serverPublicKey;
    }

    public void serverPublicKey(byte[] serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    public String pkr() {
        return pkr;
    }

    public void pkr(String pkr) {
        this.pkr = pkr;
    }

    public byte[] rgk() {
        return rgk;
    }

    public void rgk(byte[] rgk) {
        this.rgk = rgk;
    }

    public String rid() {
        return rid;
    }

    public void rid(String rid) {
        this.rid = rid;
    }

    public String deviceSn() {
        return deviceSn;
    }

    public void deviceSn(String deviceSn) {
        this.deviceSn = deviceSn;
    }

    public String mtmk() {
        return mtmk;
    }

    public String mttk() {
        return mttk;
    }

    public Status status() {
        return status;
    }

    /** Capture the master keys delivered at Step 4 and mark the scenario onboarded. */
    public void captureMasterKeys(String mtmk, String mttk) {
        this.mtmk = mtmk;
        this.mttk = mttk;
        this.status = Status.ONBOARDED;
    }

    /** @return the onboarding result, or throw if Step 4 has not completed. */
    public Onboarded requireOnboarded() {
        if (status != Status.ONBOARDED || mtmk == null || mttk == null) {
            throw new OnboardingException.NotOnboarded();
        }
        return new Onboarded(deviceSn, rid, mtmk, mttk);
    }

    /** Clear all captured state so the scenario can re-onboard from scratch. */
    public void resetKeys() {
        completed.clear();
        serverPublicKey = null;
        pkr = null;
        rgk = null;
        rid = null;
        deviceSn = null;
        mtmk = null;
        mttk = null;
        status = Status.NEW;
    }
}
