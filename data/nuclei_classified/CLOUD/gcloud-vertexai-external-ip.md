# Vulnerability: External IP Addresses Assigned to Vertex AI Notebooks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vertexai-external-ip.yaml`)

## Description
Ensure that external IP addresses are not assigned to your Google Cloud Vertex AI notebook instances, in order to help prevent data exfiltration, maintain network isolation, and meet stringent compliance requirements. Vertex AI notebook instances with an assigned external IP address can communicate with the public internet or resources in other VPC networks, which may violate security policies.

## Secure Mitigation
Re-create Vertex AI notebook instances without external IP addresses using the 'gcloud workbench instances create' command with --disable-public-ip flag. Example: gcloud workbench instances create INSTANCE_NAME --disable-public-ip

