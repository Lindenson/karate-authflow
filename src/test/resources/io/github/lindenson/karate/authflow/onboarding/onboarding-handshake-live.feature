@live
Feature: crypto backend handshake onboarding against a live backend (cleartext)

  # Connection + credentials come from -D system properties (never committed):
  #   backend.base, backend.fp, backend.login, backend.password, backend.otp, backend.accessCode
  # Device info below is demo-constant; the strategy owns all crypto.

  Background:
    * url karate.properties['backend.base']
    * def fp = karate.properties['backend.fp']

  Scenario: onboard a device end-to-end via the real crypto backend

    Given path '/api/v1/init/initial_handshake_key'
    And request { dfrgprt: '#(fp)' }
    When method post
    Then status 200
    And match response.ihshky == '#string'

    Given path '/api/v1/init'
    And request
      """
      {
        dad: { dn: 'authflow-demo', did: 'authflow-demo', sen: 'authflow-demo',
               osv: '14', imi: '000000000000000', iso: 'PlayStore' },
        dfrgprt: '#(fp)',
        fbrid:   'authflow-demo',
        lag:     'en-US'
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
