# Vulnerability: Check for Unrestricted RPC Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-rpc-access.yaml`)

## Description
Ensure that Google Cloud VPC network firewall rules do not allow unrestricted access (0.0.0.0/0 on TCP port 135). Restrict access to trusted IP addresses or ranges to reduce the attack surface and protect virtual machine (VM) instances targeted by these firewall rules.

## Secure Mitigation
Update your VPC firewall rules to allow RPC traffic only from trusted IP addresses or ranges.

