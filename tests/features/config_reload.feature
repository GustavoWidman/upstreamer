Feature: Config hot-reload

  Scenario: Add a new backend via config reload
    Given a backend on port 19601
    And upstreamer is configured with round-robin across ports 19601
    When I send 10 requests to the proxy
    Then backend 19601 should have received at least 10 requests
    When I add backend on port 19602 to the running config
    And I wait for config reload
    And I send 20 requests to the proxy
    Then each backend should have received approximately 15 requests

  Scenario: Remove a backend via config reload
    Given a backend on port 19611
    And a backend on port 19612
    And upstreamer is configured with round-robin across ports 19611, 19612
    When I send 20 requests to the proxy
    Then each backend should have received approximately 10 requests
    When I remove backend on port 19612 from the running config
    And I wait for config reload
    And I send 20 requests to the proxy
    Then backend 19611 should have received at least 20 requests
    And backend 19612 should have received at most 15 requests

  Scenario: Invalid config does not replace working config
    Given a backend on port 19621
    And upstreamer is configured with round-robin across ports 19621
    When I replace the running config with invalid content
    And I wait for config reload
    And I send 5 requests to the proxy
    Then all responses should have status 200
