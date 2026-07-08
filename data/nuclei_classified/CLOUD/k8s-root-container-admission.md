# Vulnerability: Minimize the admission of root containers
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-root-container-admission.yaml`)

## Description
Checks if any Kubernetes Deployments admit containers that run as root, which can pose a significant security risk.

## Secure Mitigation
Configure security contexts for all pods to run containers with a non-root user. Use Pod Security Policies or OPA/Gatekeeper to enforce these configurations.

