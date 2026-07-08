# Vulnerability: Pods run with root user ID
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-root-user-id.yaml`)

## Description
Checks for pods running with the user ID of the root user, increasing security risks.

## Secure Mitigation
Configure pods to run with a non-root user ID by setting the 'securityContext' for each container and the pod itself.

