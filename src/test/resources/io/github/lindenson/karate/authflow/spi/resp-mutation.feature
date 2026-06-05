Feature: post-response interceptor replaces the body

  Scenario: the scenario sees the mutated body, not the original
    Given url karate.properties['ri.base'] + '/thing'
    When method get
    Then status 200
    And match response.value == 'decrypted'
    And match response.cipher == '#notpresent'
