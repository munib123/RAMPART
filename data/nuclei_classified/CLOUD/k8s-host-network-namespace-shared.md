# Vulnerability: Host Network Namespace Sharing
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-host-network-namespace-shared.yaml`)

## Description
Checks if containers in Kubernetes Pods are configured to share the host's network namespace, which can lead to security risks.

## Secure Mitigation
Ensure that the 'hostNetwork' field is set to false in all Kubernetes Pods to prevent containers from sharing the host's network namespace.

