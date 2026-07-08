# Vulnerability: Exclude Metadata from Firewall Logging
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-exclude-metadata-from-firewall-logging.yaml`)

## Description
Ensure that Virtual Private Cloud (VPC) firewall logging is not configured to include logging metadata to reduce log file size and optimize cloud storage costs. Including metadata in firewall logs can lead to unnecessary storage costs without significant benefits.

## Secure Mitigation
Update the VPC firewall logging configuration to exclude metadata from the logs and reduce storage costs while maintaining logging efficiency.

