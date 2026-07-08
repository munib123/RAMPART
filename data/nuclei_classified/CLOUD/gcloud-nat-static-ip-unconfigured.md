# Vulnerability: Cloud NAT Gateways Not Configured with Reserved Static IPs
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-nat-static-ip-unconfigured.yaml`)

## Description
Ensure that your Google Cloud NAT gateways are configured to use static reserved external IPs in order to maintain consistent outbound IP addresses, which are critical for services requiring IP allowlisting, auditing, or compliance.

## Secure Mitigation
Configure your Google Cloud NAT gateways to use static reserved external IPs by reserving external IPs and attaching them to the NAT configuration.

