Feature: Request routing

  Scenario: Match route by path prefix
    Given a backend on port 19401 responding "api-server"
    And a backend on port 19402 responding "web-server"
    And upstreamer is configured with routes:
      | path     | origins                |
      | /api     | http://127.0.0.1:19401 |
      | /        | http://127.0.0.1:19402 |
    When I send a request to "/api/users"
    Then the response body should contain "api-server"

  Scenario: No matching route returns 404
    Given a backend on port 19411
    And upstreamer is configured with routes:
      | path     | origins                |
      | /api     | http://127.0.0.1:19411 |
    When I send a request to "/other"
    Then the response status should be 404

  Scenario: Match route by host header
    Given a backend on port 19421 responding "host-a"
    And a backend on port 19422 responding "host-b"
    And upstreamer is configured with routes:
      | host     | origins                |
      | api.test | http://127.0.0.1:19421 |
      | web.test | http://127.0.0.1:19422 |
    When I send a request with host "api.test" to "/"
    Then the response body should contain "host-a"

  Scenario: Wildcard host matches any host
    Given a backend on port 19431
    And upstreamer is configured with routes:
      | host | origins                |
      | *    | http://127.0.0.1:19431 |
    When I send a request with host "anything.example.com" to "/"
    Then the response status should be 200
