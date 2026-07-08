# Vulnerability: Unrestricted Access to Memcached
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-memcached.yaml`)

## Description
Detects unrestricted inbound access to Memcached on Amazon EC2 instances, which can lead to cache poisoning, unauthorized access, and DDoS attacks.

## Secure Mitigation
Restrict inbound access to Memcached by updating EC2 security group rules to allow only trusted IPs to connect on TCP/UDP port 11211.

