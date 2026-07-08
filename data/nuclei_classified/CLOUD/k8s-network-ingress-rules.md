# Vulnerability: Define network ingress rules
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-network-ingress-rules.yaml`)

## Description
Checks if Kubernetes network policies define specific ingress rules, which can help secure network communication within the cluster.

## Secure Mitigation
Define specific ingress rules in all network policies to control the flow of inbound traffic to pods, ensuring only authorized traffic can access cluster resources.

