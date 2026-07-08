# Vulnerability: CPU Requests not set in Deployments
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-cpu-requests-not-set.yaml`)

## Description
Checks for missing CPU requests in Kubernetes Deployments, which can lead to inadequate scheduling and resource allocation.

## Secure Mitigation
Set CPU requests for all containers in Kubernetes Deplayments to ensure efficient scheduling and resource allocation.

