# Vulnerability: Check for Unrestricted Inbound Access on Uncommon Ports
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-inbound-uncommon-ports.yaml`)

## Description
Ensure that your Virtual Private Cloud (VPC) firewall rules do not allow unrestricted access (0.0.0.0/0) to any uncommon ports to protect against brute force attacks targeting virtual machine instances associated with these firewall rules. Uncommon ports are TCP/UDP ports not included in the common service ports category.

## Secure Mitigation
Update your VPC firewall rules to allow traffic only to common ports required for your applications, and restrict access to uncommon ports.

