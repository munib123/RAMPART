# Vulnerability: Unrestricted Admin Port Access
**Classification:** CLOUD
**Source:** Nuclei Template (`unrestricted-admin-ports.yaml`)

## Description
Checks for unrestricted ingress on TCP ports 22 (SSH) and 3389 (RDP) in Amazon VPC NACLs, exposing remote server administration to potentially malicious traffic.

## Secure Mitigation
Restrict access to ports 22 and 3389 to trusted IPs or IP ranges to adhere to the Principle of Least Privilege (POLP).

