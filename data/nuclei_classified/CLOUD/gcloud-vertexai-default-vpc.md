# Vulnerability: Default VPC Network In Use for Vertex AI Notebooks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vertexai-default-vpc.yaml`)

## Description
Ensure that your Google Cloud Vertex AI notebook instances are not created within the default Virtual Private Cloud (VPC) network. The default VPC comes with predefined, over-permissive firewall rules that are not included in audit logging. While suitable for quick starts, complex production AI applications with multi-tier architectures may require private network segments or customization.

## Secure Mitigation
Re-create Vertex AI notebook instances in a custom VPC network with properly configured subnets and firewall rules. Use the 'gcloud workbench instances create' command with appropriate network and subnet parameters.

