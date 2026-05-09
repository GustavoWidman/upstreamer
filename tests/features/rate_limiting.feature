Feature: Rate limiting

  Scenario: Requests under rate limit succeed
    Given a backend on port 19201
    And upstreamer is configured with a rate limit of 100 requests/sec burst 200
    When I send 50 requests to the proxy
    Then all responses should have status 200

  Scenario: Requests over rate limit return 429
    Given a backend on port 19201
    And upstreamer is configured with a rate limit of 10 requests/sec burst 10
    When I send 50 requests to the proxy
    Then at least one response should have status 429

  Scenario: Rate limit is per-route
    Given a backend on port 19201 responding "limited"
    And a backend on port 19202 responding "unlimited"
    And upstreamer is configured with routes:
      | path | origins                | rate | burst |
      | /api | http://127.0.0.1:19201 | 5    | 5     |
      | /    | http://127.0.0.1:19202 |      |       |
    When I send 20 requests to "/api"
    And I send 20 requests to "/"
    Then at least one response to "/api" should have status 429
    And all responses to "/" should have status 200
