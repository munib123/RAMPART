# Vulnerability: Open Inbound NACL Traffic
**Classification:** CLOUD
**Source:** Nuclei Template (`nacl-open-inbound.yaml`)

## Description
Checks for Amazon VPC Network ACLs with inbound rules allowing traffic from all IPs across all ports, increasing the risk of unauthorized access.

## Secure Mitigation
Restrict Network ACL inbound rules to only allow necessary IP ranges and ports as per the Principle of Least Privilege.

