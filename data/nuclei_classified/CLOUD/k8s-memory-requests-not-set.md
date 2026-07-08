# Vulnerability: Memory requests not set in Deployments
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-memory-requests-not-set.yaml`)

## Description
Checks for missing memory requests in Kubernetes Deployments, which can lead to inefficient scheduling and potential node resource exhaustion.

## Secure Mitigation
Set memory requests for all containers in Kubernetes Deployments to ensure efficient pod scheduling and node resource utilization.

