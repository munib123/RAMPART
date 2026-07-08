# Vulnerability: Check for VPC Firewall Rules with Port Ranges
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vpc-firewall-port-ranges.yaml`)

## Description
Ensure that your Google Cloud VPC network firewall rules don't have ranges of ports configured to allow inbound traffic. This protects associated virtual machine instances against Denial-of-Service (DoS) attacks or brute-force attacks. It is recommended to open only specific ports within your firewall rules based on your application requirements.

## Secure Mitigation
Update your VPC firewall rules to allow only specific ports required for your applications, rather than a range of ports.

