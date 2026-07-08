# Vulnerability: VPC Peering Usage Not Restricted
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-vpc-peering.yaml`)

## Description
Ensure that the VPC networks that are allowed to be peered with the networks created for your project, folder, or organization, are defined using the "Restrict VPC Peering Usage" constraint policy. This constraint helps you achieve regulatory compliance by explicitly defining the resource name of each Virtual Private Cloud (VPC) network allowed for VPC peering.

## Secure Mitigation
Configure the "Restrict VPC Peering Usage" policy at the organization level to explicitly specify which VPC networks can be peered. Use the format projects/<project-id>/global/networks/<vpc-network-name> or under: prefix for broader scopes.

