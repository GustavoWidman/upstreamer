Feature: Backend health and failover

  Scenario: Failing backend gets removed from rotation
    Given a backend on port 19101
    And a backend on port 19102
    And upstreamer is configured with round-robin across ports 19101, 19102
    When I send 6 requests to the proxy
    Then each backend should have received approximately 3 requests

  Scenario: Backend returning 5xx triggers passive health check
    Given a backend on port 19101 returning status 500
    And a backend on port 19102
    And upstreamer is configured with round-robin across ports 19101, 19102
    When I send 30 requests to the proxy
    Then backend 19102 should have received most of the requests

  Scenario: Backend returning 4xx does not trigger health check
    Given a backend on port 19101 returning status 403
    And a backend on port 19102
    And upstreamer is configured with round-robin across ports 19101, 19102
    When I send 20 requests to the proxy
    Then each backend should have received approximately 10 requests

  Scenario: All backends down returns 502
    Given a backend on port 19101 returning status 500
    And a backend on port 19102 returning status 500
    And upstreamer is configured with round-robin across ports 19101, 19102
    When I send 30 requests to the proxy
    Then the proxy should still respond with 502
