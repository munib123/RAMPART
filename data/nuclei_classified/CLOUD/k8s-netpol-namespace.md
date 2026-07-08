# Vulnerability: Network Policies specify namespace
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-netpol-namespace.yaml`)

## Description
Checks for Kubernetes Network Policies that do not specify a namespace, which can lead to potential misconfigurations and security issues.

## Secure Mitigation
Ensure that all Network Policies explicitly define a namespace to maintain proper network isolation and security boundaries.

