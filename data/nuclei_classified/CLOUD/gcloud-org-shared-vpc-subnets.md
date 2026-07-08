# Vulnerability: Shared VPC Subnetworks Not Restricted
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-shared-vpc-subnets.yaml`)

## Description
Ensure that the set of shared VPC subnetworks that eligible Google Cloud resources can use, are defined using the "Restrict Shared VPC Subnetworks" constraint policy. The allowed list of VPC subnetworks must be specified in the following form: projects/<project-id>/regions/<subnetwork-region>/subnetworks/<subnetwork-name>. You can also define the list of allowed subnetworks in a project, folder, or organization.

## Secure Mitigation
Configure the "Restrict Shared VPC Subnetworks" policy at the organization level to explicitly specify which VPC subnetworks can be used. Use the format projects/<project-id>/regions/<region>/subnetworks/<name> or under: prefix for broader scopes.

