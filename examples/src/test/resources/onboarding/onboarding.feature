@onboarding
Feature: encrypted device onboarding + STTK working flow via karate-authflow

  # No crypto, base64, rid, rgke, dsn, session-key derivation or MAC here — the plugin
  # owns all of it. The scenario reads decrypted (cleartext) responses end to end:
  # onboarding runs under the RGK envelope, the final language call under the per-request
  # STTK session key with an STMK MAC.

  Background:
    * url karate.properties['backend.base']

  Scenario: a device onboards (handshake), receives master keys, then changes its language under STTK

    # Step 0 — handshake: fetch the crypto-backend public key (HANDSHAKE flavor, 5 steps)
    Given path '/api/v1/init/initial_handshake_key'
    And request { dfrgprt: 'fingerprint-123' }
    When method post
    Then status 200

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

    # Step 5 — working flow under the per-request STTK session key (change device language).
    # The plugin derives STTK/STMK from the master keys + rid, encrypts the body, MACs it,
    # then verifies and decrypts the response — all transparent.
    Given path '/api/v1/devices/language'
    And request { language: 'en' }
    When method post
    Then status 200
