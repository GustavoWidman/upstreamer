Feature: Round-robin load balancing

  Scenario: Distribute requests evenly across 3 backends
    Given 3 backends running on ports 19301, 19302, 19303
    And upstreamer is configured with round-robin across all 3 backends
    When I send 30 requests to the proxy
    Then each backend should have received approximately 10 requests

  Scenario: Single backend receives all traffic
    Given 1 backend running on port 19301
    And upstreamer is configured with round-robin across 1 backend
    When I send 10 requests to the proxy
    Then the backend should have received 10 requests

  Scenario: Requests are proxied with correct path
    Given 1 backend running on port 19301
    And upstreamer is configured with round-robin across 1 backend
    When I send 5 requests to "/api/test"
    Then the backend should have received requests to "/api/test"
