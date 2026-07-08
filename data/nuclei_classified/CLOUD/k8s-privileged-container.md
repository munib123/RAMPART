# Vulnerability: Privileged Containers Found in Deployments
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-privileged-container.yaml`)

## Description
Checks for containers running in privileged mode within Kubernetes Deployments, and now also checks for user privileges and privilege escalation settings.

## Secure Mitigation
Ensure that no container in Kubernetes Deployments runs in privileged mode, as the root user, or with privilege escalation enabled. Modify the security context for each container to set `privileged: false`, `runAsUser` appropriately, and `allowPrivilegeEscalation: false`.

