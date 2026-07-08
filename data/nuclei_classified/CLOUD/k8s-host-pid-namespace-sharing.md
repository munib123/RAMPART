# Vulnerability: Host PID Namespace Sharing
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-host-pid-namespace-sharing.yaml`)

## Description
Checks if containers in Kubernetes pods share the host's process ID namespace, which can pose a security risk.

## Secure Mitigation
Ensure that the 'hostPID' field is set to 'false' in Kubernetes Pod specifications to prevent containers from sharing the host's PID namespace.

