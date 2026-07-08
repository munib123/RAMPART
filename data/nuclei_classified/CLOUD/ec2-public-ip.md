# Vulnerability: Public IP on EC2 Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-public-ip.yaml`)

## Description
Ensures Amazon EC2 instances, especially backend ones, do not use public IP addresses to minimize Internet exposure.

## Secure Mitigation
Restrict public IP assignment for EC2 instances, particularly for backend instances. Use private IPs and manage access via AWS VPC and security groups.

