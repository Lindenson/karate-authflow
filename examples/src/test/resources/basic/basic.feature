Feature: HTTP Basic auth via karate-authflow

  # No auth steps here — BasicAuthStrategy injects the Authorization header.

  Scenario: a protected endpoint authenticates transparently
    Given url 'https://postman-echo.com/basic-auth'
    When method get
    Then status 200
    And match response.authenticated == true
