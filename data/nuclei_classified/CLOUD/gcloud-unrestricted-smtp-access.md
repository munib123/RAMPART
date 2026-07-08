# Vulnerability: Check for Unrestricted SMTP Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-smtp-access.yaml`)

## Description
Ensure that Google Cloud VPC network firewall rules do not allow unrestricted access (0.0.0.0/0 on TCP port 25). Restrict access to trusted IP addresses or ranges to reduce the risk of security threats for the SMTP server instances associated with these firewall rules.

## Secure Mitigation
Update your VPC firewall rules to allow SMTP traffic only from trusted IP addresses or ranges.

