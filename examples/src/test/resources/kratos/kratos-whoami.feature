Feature: Ory Kratos session auth via karate-authflow

  # No login steps here — KratosSessionStrategy logs in once and injects the
  # ory_kratos_session cookie, so this protected call to Kratos just works.

  Scenario: the Kratos whoami endpoint reports an active session
    Given url 'http://127.0.0.1:4433/sessions/whoami'
    When method get
    Then status 200
    And match response.active == true
    And match response.identity.traits.email == 'demo@example.com'
