@onboarding @standard
Feature: TMS device onboarding — standard flavor (cleartext)

  # No crypto, base64, rid, rgke or dsn here — the strategy owns all of that.

  Background:
    * url karate.properties['tms.base']

  Scenario: a new device onboards and receives master keys

    # Step 1 — Init (RGK exchange + AppData)
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
