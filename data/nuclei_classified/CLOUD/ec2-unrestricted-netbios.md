# Vulnerability: Unrestricted NetBIOS Access in EC2
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-netbios.yaml`)

## Description
Checks for inbound rules in Amazon EC2 security groups that allow unrestricted access on TCP port 139 and UDP ports 137 and 138, increasing the risk of unauthorized access and potential security breaches.

## Secure Mitigation
Restrict access to TCP port 139 and UDP ports 137 and 138 in EC2 security groups. Implement strict access control based on the principle of least privilege.

