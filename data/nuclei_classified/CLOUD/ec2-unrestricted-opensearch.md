# Vulnerability: Unrestricted OpenSearch Access
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-opensearch.yaml`)

## Description
Checks EC2 security groups for inbound rules allowing unrestricted access to OpenSearch on TCP port 9200. Restricts access to essential IP addresses only.

## Secure Mitigation
Modify EC2 security group rules to limit access to TCP port 9200 for OpenSearch, allowing only necessary IPs, implementing the principle of least privilege.

