@onboarding
Feature: encrypted device onboarding via karate-authflow

  # No crypto, base64, rid, rgke or dsn here — EncryptedOnboardingStrategy owns all of
  # that. The scenario reads decrypted (cleartext) responses.

  Background:
    * url karate.properties['backend.base']

  Scenario: a device onboards and receives master keys

    # Step 1 — init (RGK exchange + device info)
    Given path '/api/v1/init'
    And request
      """
      {
        dad: { dn: 'Pixel 7', did: 'device-1', sen: 'serial-1',
               osv: '14', imi: 'imei-1', iso: 'PlayStore' },
        dfrgprt: 'fingerprint-123',
        fbrid:   'firebase-token-1',
        lag:     'en-US'
      }
      """
    When method post
    Then status 200
    And match response.deviceSn == '#string'

    # Step 2 — credentials
    Given path '/api/v1/init/credentials'
    And request { ussLg: 'user@example.com', urrPsa: 'p@ssw0rd' }
    When method put
    Then status 200

    # Step 3 — confirm OTP (the strategy fills the OTP from config)
    Given path '/api/v1/init/otp/confirm-otp'
    And request { otp: '000000', reLLo7eh: 'user@example.com', timezone: 'Europe/Kyiv' }
    When method put
    Then status 200

    # Step 4 — access code register (master keys issued)
    Given path '/api/v1/init/access-code/register'
    And request { acd: '9999', otp: 'VERIFY', atp: 'CODE' }
    When method put
    Then status 200
    And match response.mttk == '#string'
    And match response.mtmk == '#string'
