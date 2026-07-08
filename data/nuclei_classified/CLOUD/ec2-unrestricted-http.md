# Vulnerability: Unrestricted HTTP on EC2
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-http.yaml`)

## Description
Checks for inbound rules in EC2 security groups allowing unrestricted access (0.0.0.0/0) to TCP port 80, increasing exposure to potential breaches.

## Secure Mitigation
Restrict inbound traffic on TCP port 80 to only necessary IP addresses, adhering to the principle of least privilege.

