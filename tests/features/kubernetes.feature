@kubernetes
Feature: Kubernetes smoke coverage

  Scenario: Kubernetes routing works
    Given a kind cluster running upstreamer from the Kubernetes manifests
    Then the Kubernetes proxy should route to the backend

  Scenario: Kubernetes health endpoint works
    Given a kind cluster running upstreamer from the Kubernetes manifests
    Then the Kubernetes health endpoint should return status 200

  Scenario: Kubernetes rate limiting works
    Given a kind cluster running upstreamer from the Kubernetes manifests
    When I send 200 rapid requests to the Kubernetes proxy
    Then at least 1 Kubernetes responses should have status 429

  Scenario: Kubernetes metrics are exposed
    Given a kind cluster running upstreamer from the Kubernetes manifests
    Then the Kubernetes proxy should route to the backend
    And I wait for Kubernetes self-metrics to be collected
    And the Kubernetes metrics should contain "upstreamer_total_origins"

  Scenario: Kubernetes config hot-reload updates rate limiting
    Given a kind cluster running upstreamer from the Kubernetes manifests
    When I patch the Kubernetes config rate limit to 10 requests/sec burst 15
    And I wait 10 seconds for the Kubernetes config reload
    And I send 30 rapid requests to the Kubernetes proxy
    Then more than 10 Kubernetes responses should have status 429
