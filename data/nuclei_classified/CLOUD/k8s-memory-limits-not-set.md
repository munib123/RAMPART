# Vulnerability: Memory limits not set in Deployments
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-memory-limits-not-set.yaml`)

## Description
Checks for missing memory limits in Kubernetes Deployments, which can lead to resource contention and instability

## Secure Mitigation
Set memory limits for all containers in Kubernetes Deployments to ensure resource management and application stability

