# Vulnerability: Minimize container added capabilities
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-minimize-added-capabilities.yaml`)

## Description
Checks for containers in Kubernetes Deployments with added capabilities beyond the default set, increasing security risks.

## Secure Mitigation
Ensure that no unnecessary capabilities are added to containers within Kubernetes Deployments. Use security contexts to define the minimum necessary privileges.

