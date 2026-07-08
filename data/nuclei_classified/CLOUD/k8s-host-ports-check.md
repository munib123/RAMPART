# Vulnerability: Host ports should not be used
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-host-ports-check.yaml`)

## Description
Checks Kubernetes Deployments to ensure they are not configured to use host ports, which can expose the host to potential security risks.

## Secure Mitigation
Avoid using host ports in Kubernetes Deployments. Use services or other networking mechanisms to expose container applications.

