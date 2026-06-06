@onboarding @ukrsib
Feature: TMS device onboarding — ukrsib flavor (cleartext)

  # Same as standard, but prepended with the Step 0 handshake that fetches the
  # per-device TMS public key. The strategy captures it; no crypto in the feature.

  Background:
    * url karate.properties['tms.base']

  Scenario: a new device handshakes, then onboards and receives master keys

    # Step 0 — initial handshake (plain JSON)
    Given path '/api/v1/init/initial_handshake_key'
    And request { dfrgprt: 'fingerprint-123' }
    When method post
    Then status 200
    And match response.ihshky == '#string'

    # Step 1 — Init
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

    # Step 2 — Credentials
    Given path '/api/v1/init/credentials'
    And request { ussLg: 'user@example.com', urrPsa: 'p@ssw0rd' }
    When method put
    Then status 200

    # Step 3 — Confirm OTP
    Given path '/api/v1/init/otp/confirm-otp'
    And request { otp: '1234', reLLo7eh: 'user@example.com', timezone: 'Europe/Kyiv' }
    When method put
    Then status 200

    # Step 4 — Access code register (master keys issued)
    Given path '/api/v1/init/access-code/register'
    And request { acd: '9999', otp: 'VERIFY', atp: 'CODE' }
    When method put
    Then status 200
    And match response.mttk == '#string'
    And match response.mtmk == '#string'
