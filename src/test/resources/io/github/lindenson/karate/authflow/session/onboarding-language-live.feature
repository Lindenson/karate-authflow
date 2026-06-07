Feature: onboard then change device language under STTK (live, cleartext)

  # Connection + credentials from -D system properties (never committed):
  #   backend.base, backend.fp, backend.login, backend.password, backend.otp, backend.accessCode
  # Steps 0-4 onboard (RGK); the final step runs under STTK with a MAC — all transparent.

  Background:
    * url karate.properties['backend.base']
    * def fp = karate.properties['backend.fp']

  Scenario: full journey — handshake onboarding, then POST /api/v1/devices/language

    Given path '/api/v1/init/initial_handshake_key'
    And request { dfrgprt: '#(fp)' }
    When method post
    Then status 200

    Given path '/api/v1/init'
    And request
      """
      {
        dad: { dn: 'authflow-demo', did: 'authflow-demo', sen: 'authflow-demo',
               osv: '14', imi: '000000000000000', iso: 'PlayStore' },
        dfrgprt: '#(fp)', fbrid: 'authflow-demo', lag: 'en-US'
      }
      """
    When method post
    Then status 200
    And match response.deviceSn == '#string'

    Given path '/api/v1/init/credentials'
    And request { ussLg: '#(karate.properties["backend.login"])', urrPsa: '#(karate.properties["backend.password"])' }
    When method put
    Then status 200

    Given path '/api/v1/init/otp/confirm-otp'
    And request { otp: '#(karate.properties["backend.otp"])', reLLo7eh: '#(karate.properties["backend.login"])', timezone: 'Europe/Kyiv' }
    When method put
    Then status 200

    Given path '/api/v1/init/access-code/register'
    And request { acd: '#(karate.properties["backend.accessCode"])', otp: 'VERIFY', atp: 'CODE' }
    When method put
    Then status 200
    And match response.mttk == '#string'
    And match response.mtmk == '#string'

    # --- working flow under STTK ---
    Given path '/api/v1/devices/language'
    And request { language: 'en-US' }
    When method post
    Then status 200
