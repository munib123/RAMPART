# Vulnerability: Ensure namespaces are utilized
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-ns-usage-check.yaml`)

## Description
Checks if Kubernetes namespaces are actively used to separate resources, which is critical for resource organization and access control.

## Secure Mitigation
Implement and use namespaces to organize resources within the Kubernetes cluster effectively. Define access controls and resource quotas on a per-namespace basis.

