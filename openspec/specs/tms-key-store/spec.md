# tms-key-store Specification

## Purpose
TBD - created by archiving change tms-onboarding-strategy. Update Purpose after archive.
## Requirements
### Requirement: Per-scenario crypto state

The strategy SHALL keep its onboarding crypto state (RGK, sticky `rid`, `deviceSn`, completed steps, captured master keys) isolated per scenario, keyed by `scenarioId()`, so scenarios running under `Runner.parallel(n)` never share or corrupt each other's state.

#### Scenario: Parallel scenarios are isolated
- **WHEN** two scenarios onboard concurrently through one shared strategy instance
- **THEN** each has its own `rid`, RGK, and `deviceSn`, and neither observes the other's keys

### Requirement: Master keys captured at Step 4

On a successful Step 4 the strategy SHALL capture `mTMK` and `mTTK` from the decrypted response into the scenario's key store, and mark the scenario onboarded.

#### Scenario: mTMK and mTTK retained
- **WHEN** Step 4 succeeds with `{mttk, mtmk}`
- **THEN** the scenario's key store exposes `mTMK`, `mTTK`, `deviceSn`, and `rid`, and reports status onboarded

### Requirement: Retention and reset

Captured keys SHALL persist in memory for the scenario until an explicit `resetKeys()`; reset SHALL clear the keys and completed steps so the scenario can re-onboard from scratch. There is no time-based expiry.

#### Scenario: Reset clears state
- **WHEN** `resetKeys()` is called for a scenario
- **THEN** its key store is empty and its completed steps are cleared

### Requirement: Accessor for follow-up flows

The key store SHALL provide a `requireOnboarded()` accessor that returns `{mTMK, mTTK, deviceSn, rid}` when onboarding completed, or fails clearly if it did not — the contract by which later (transaction) flows consume the onboarding result.

#### Scenario: Require before onboarded fails
- **WHEN** `requireOnboarded()` is called before Step 4 completed
- **THEN** it fails with a clear "not onboarded" error

