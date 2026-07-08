# Vulnerability: Cloud SQL Authorized Networks Not Restricted
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-sql-authorized-networks.yaml`)

## Description
Ensure that "Restrict Authorized Networks on Cloud SQL instances" policy is enforced for your Google Cloud Platform (GCP) organization to deny IAM members to add authorized networks in order to provide access to your security-critical SQL database instances. By default, authorized networks can be added to any Cloud SQL database instance.

## Secure Mitigation
Enable the "Restrict Authorized Networks on Cloud SQL instances" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the sql.restrictAuthorizedNetworks constraint.

