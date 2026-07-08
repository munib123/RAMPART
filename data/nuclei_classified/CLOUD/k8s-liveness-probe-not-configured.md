# Vulnerability: Liveness Probe Not Configured in Deployments
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-liveness-probe-not-configured.yaml`)

## Description
Checks for missing liveness probes in Kubernetes Deployments, which are essential for managing container health and automatic recovery

## Secure Mitigation
Configure liveness probes for all containers in Kubernetes Deployments to ensure proper health checks and automatic restarts of failing containers

