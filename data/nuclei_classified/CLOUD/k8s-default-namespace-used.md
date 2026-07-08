# Vulnerability: Default Namespace Usage in Deployments
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-default-namespace-used.yaml`)

## Description
Checks if Kubernetes Deployments are using the default namespace, which can lead to security risks and mismanagement issues.

## Secure Mitigation
Avoid using the default namespace for Kubernetes Deployments. Create and specify dedicated namespaces tailored to specific applications or teams to enhance security and manage resources effectively.

