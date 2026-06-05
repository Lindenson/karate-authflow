Feature: scenario id is stable per scenario

  Background:
    * url karate.properties['ri.base']

  Scenario: alpha makes two calls
    Given path 'ping'
    When method get
    Then status 200
    Given path 'ping'
    When method get
    Then status 200

  Scenario: beta makes two calls
    Given path 'ping'
    When method get
    Then status 200
    Given path 'ping'
    When method get
    Then status 200
