# Vulnerability: EKS Long Running Pods
**Classification:** CLOUD
**Source:** Nuclei Template (`eks-long-running-pods.yaml`)

## Description
Ensure that Amazon Elastic Kubernetes Service (EKS) clusters do not have pods running for more than 30 days. Long-running pods may indicate stale deployments, potential security risks, or resource inefficiencies.

## Secure Mitigation
Review and update long-running pods. Consider implementing proper deployment strategies, regular updates, and automated pod rotation policies.

