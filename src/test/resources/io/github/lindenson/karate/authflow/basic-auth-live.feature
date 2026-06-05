@live
Feature: transparent HTTP Basic authentication

  # Note: this feature contains NO authentication steps. Credentials are injected
  # by karate-authflow's registered BasicAuthStrategy, proving the interceptor is
  # transparent to test authors.

  Scenario: an auth-free request is authenticated by authflow
    Given url 'https://postman-echo.com/basic-auth'
    When method get
    Then status 200
    And match response.authenticated == true
