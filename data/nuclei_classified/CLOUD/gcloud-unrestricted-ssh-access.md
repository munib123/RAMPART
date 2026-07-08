# Vulnerability: Check for Unrestricted SSH Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-ssh-access.yaml`)

## Description
Ensure that your Google Cloud VPC firewall rules do not allow unrestricted SSH access (0.0.0.0/0 on TCP port 22). Restrict SSH access to trusted IP addresses or ranges to reduce the attack surface and adhere to the principle of least privilege.

## Secure Mitigation
Update your VPC firewall rules to allow SSH traffic only from trusted IP addresses or ranges.

