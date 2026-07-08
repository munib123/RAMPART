# Vulnerability: Check for Unrestricted Outbound Access on All Ports
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-outbound-access.yaml`)

## Description
Check your Google Cloud VPC network firewall for any egress rules that allow unrestricted access (0.0.0.0/0) to any TCP/UDP ports. Restrict outbound traffic to only those IP addresses and/or IP ranges that require it in order to implement the principle of least privilege and reduce the attack surface.

## Secure Mitigation
Update your VPC firewall rules to restrict outbound traffic to trusted IP addresses and ports only.

