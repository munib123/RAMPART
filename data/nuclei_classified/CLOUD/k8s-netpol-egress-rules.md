# Vulnerability: Network policies define egress rules
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-netpol-egress-rules.yaml`)

## Description
Checks for network policies in Kubernetes that do not define egress rules, which can leave the network exposed to external threats.

## Secure Mitigation
Define egress rules in all network policies to control outbound traffic from your Kubernetes pods, thereby reducing security risks.

