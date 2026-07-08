# Vulnerability: Set appropriate seccomp profile
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-seccomp-profile-set.yaml`)

## Description
Checks if the seccomp profile is set to docker/default or runtime/default in Kubernetes Deployments.

## Secure Mitigation
Ensure that all containers in Kubernetes Deployments have a seccomp profile of docker/default or runtime/default set in their security contexts.

