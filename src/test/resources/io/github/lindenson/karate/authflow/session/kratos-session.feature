Feature: transparent Kratos session authentication

  # No login steps here. KratosSessionStrategy logs in to Kratos once and injects
  # the ory_kratos_session cookie, so this protected request just works.

  Scenario: a protected endpoint is reachable without any auth steps
    Given url karate.properties['kratos.base'] + '/protected'
    When method get
    Then status 200
    And match response.ok == true
