# Vulnerability: Check for Unrestricted ICMP Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-icmp-access.yaml`)

## Description
Ensure that your Google Cloud VPC network firewall rules do not allow unrestricted access (0.0.0.0/0) using ICMP. Restrict ICMP-based access to trusted IP addresses or IP ranges to implement the principle of least privilege (POLP) and reduce the attack surface.

## Secure Mitigation
Update your VPC firewall rules to restrict ICMP-based access to trusted IP addresses or ranges only.

