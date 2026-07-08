# Vulnerability: Default VPC Network In Use
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-default-vpc-in-use.yaml`)

## Description
Ensure that your Google Cloud Platform (GCP) projects are not using the default Virtual Private Cloud (VPC) network. Using the default VPC network does not adhere to security best practices and may not meet specific networking requirements.

## Secure Mitigation
Delete the default VPC network and create custom VPC networks with tailored configurations to meet your organization's security and networking requirements.

