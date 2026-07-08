# Vulnerability: Default Network Creation Not Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-default-network.yaml`)

## Description
Ensure that "Skip Default Network Creation" constraint policy is enforced for your Google Cloud Platform (GCP) organizations in order to follow security best practices and meet networking requirements. Once enabled, this constraint skips the creation of the default Virtual Private Cloud (VPC) network and related resources during Google Cloud project creation.

## Secure Mitigation
Enable the "Skip Default Network Creation" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the compute.skipDefaultNetworkCreation constraint.

