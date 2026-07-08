# Vulnerability: NAT Gateway Subnets Not Restricted to Specific VPCs
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-nat-subnet-unrestricted.yaml`)

## Description
Ensure that your Google Cloud NAT gateways are mapped only to specific VPC subnets to maintain controlled and secure outbound Internet access, minimize unintended traffic exposure, and optimize resource usage within your network design. This promotes network isolation and ensures adherence to your organization's stringent compliance requirements.

## Secure Mitigation
Restrict your Cloud NAT gateways to specific VPC subnets by defining subnet mappings in the NAT configuration settings. Review and update your network configurations to ensure adherence to your organization's security policies.

