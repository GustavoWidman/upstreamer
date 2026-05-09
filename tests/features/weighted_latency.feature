Feature: Weighted-latency load balancing

  Scenario: Distribute traffic evenly when backends have equal latency
    Given a backend on port 19501
    And a backend on port 19502
    And upstreamer is configured with weighted-latency balancing
    When I send 60 requests to the proxy
    Then all responses should have status 200
    And each backend should have received approximately 30 requests

  Scenario: Fast backend receives more traffic than slow backend
    Given a backend on port 19511
    And a slow backend on port 19512 with 50ms delay
    And upstreamer is configured with weighted-latency balancing
    When I send 60 requests to the proxy
    Then all responses should have status 200
    And backend 19511 should have received most of the requests
