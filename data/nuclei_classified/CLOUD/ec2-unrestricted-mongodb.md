# Vulnerability: Unrestricted MongoDB Access in EC2
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-mongodb.yaml`)

## Description
Identifies open access to MongoDB in AWS EC2 security groups, where inbound rules allow unrestricted access (0.0.0.0/0 or ::/0) to TCP port 27017. This poses a significant risk as it can lead to unauthorized access and potential data breaches.

## Secure Mitigation
Restrict MongoDB's TCP port 27017 access in EC2 security groups to only those IP addresses that require it, adhering to the principle of least privilege.

