@kubernetes
Feature: Kubernetes smoke coverage

  Scenario: Run the kind-based smoke test through Behave
    Given a kind cluster running upstreamer from the Kubernetes manifests
    Then the Kubernetes proxy should route to the backend
    And the Kubernetes health endpoint should return status 200
    When I send 200 rapid requests to the Kubernetes proxy
    Then at least 1 Kubernetes responses should have status 429
    And I wait for Kubernetes self-metrics to be collected
    And the Kubernetes metrics should contain "upstreamer_total_origins"
    When I patch the Kubernetes config rate limit to 10 requests/sec burst 15
    And I wait 10 seconds for the Kubernetes config reload
    And I send 30 rapid requests to the Kubernetes proxy
    Then more than 10 Kubernetes responses should have status 429
