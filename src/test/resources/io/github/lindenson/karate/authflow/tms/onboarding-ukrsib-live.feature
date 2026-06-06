@live
Feature: TMS ukrsib onboarding against a live backend (cleartext)

  # Connection + credentials come from -D system properties (never committed):
  #   tms.base, tms.fp, tms.login, tms.password, tms.otp, tms.accessCode
  # Device info below is demo-constant; the strategy owns all crypto.

  Background:
    * url karate.properties['tms.base']
    * def fp = karate.properties['tms.fp']

  Scenario: onboard a device end-to-end via the real TMS

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
    And request { ussLg: '#(karate.properties["tms.login"])', urrPsa: '#(karate.properties["tms.password"])' }
    When method put
    Then status 200

    Given path '/api/v1/init/otp/confirm-otp'
    And request { otp: '#(karate.properties["tms.otp"])', reLLo7eh: '#(karate.properties["tms.login"])', timezone: 'Europe/Kyiv' }
    When method put
    Then status 200

    Given path '/api/v1/init/access-code/register'
    And request { acd: '#(karate.properties["tms.accessCode"])', otp: 'VERIFY', atp: 'CODE' }
    When method put
    Then status 200
    And match response.mttk == '#string'
    And match response.mtmk == '#string'
