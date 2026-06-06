@live
Feature: TMS ukrsib onboarding up to credentials (live, stops before OTP)

  # Steps 0–2 only: handshake, init (deviceSn), credentials (validates the
  # password and makes the server generate + send the OTP). No OTP/access-code.

  Background:
    * url karate.properties['tms.base']
    * def fp = karate.properties['tms.fp']

  Scenario: handshake, init and credentials succeed

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
