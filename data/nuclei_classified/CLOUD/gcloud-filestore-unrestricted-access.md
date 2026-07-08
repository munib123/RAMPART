# Vulnerability: Filestore Instance Client Access Not Restricted by IP
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-filestore-unrestricted-access.yaml`)

## Description
Ensure that client access to your Google Cloud Filestore instances is limited to specific (trusted) IP addresses or IP address ranges in order to protect your data against unauthorized access. By default, Filestore instances provide full (root-level read/write) access to all clients within the same Google Cloud project and VPC network.

## Secure Mitigation
Configure IP-based access rules for your Filestore instances to restrict access to specific IP addresses or ranges. Once configured, any IP address or range not explicitly allowed will be denied access.

