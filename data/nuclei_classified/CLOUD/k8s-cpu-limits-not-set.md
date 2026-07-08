# Vulnerability: CPU limits not set in Deployments
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-cpu-limits-not-set.yaml`)

## Description
Checks for missing CPU limits in Kubernetes Deployments, which can lead to excessive CPU usage and affect other applications

## Secure Mitigation
Set CPU limits for all containers in Kubernetes Deployments to ensure fair CPU resource distribution and prevent performance issues.

