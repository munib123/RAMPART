# Vulnerability: Check for Legacy Networks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-check-legacy-networks.yaml`)

## Description
Ensure that your Google Cloud Platform (GCP) projects are not using legacy networks. Legacy networks are no longer recommended for production environments as they do not support advanced networking features. It is strongly advised to use Virtual Private Cloud (VPC) networks instead.

## Secure Mitigation
Migrate your GCP project from legacy networks to Virtual Private Cloud (VPC) networks to utilize the latest networking capabilities.

