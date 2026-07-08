# Vulnerability: Check for Missing Network Policies in Kubernetes
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-missing-network-policies.yaml`)

## Description
Checks if any network policies are defined across all namespaces in the Kubernetes cluster.

## Secure Mitigation
Define and apply network policies to manage ingress and egress traffic within namespaces effectively. Use `kubectl apply -f <network-policy-file.yaml>` to enforce network boundaries.

