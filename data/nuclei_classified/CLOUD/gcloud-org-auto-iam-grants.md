# Vulnerability: Automatic IAM Role Grants for Default Service Accounts Not Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-auto-iam-grants.yaml`)

## Description
Ensure that "Disable Automatic IAM Grants for Default Service Accounts" policy is enforced for your Google Cloud Platform (GCP) organizations and projects in order to deactivate the automatic IAM role grant for default service accounts. When a default service account is created, it is automatically granted the Editor role ("roles/editor") on your project.

## Secure Mitigation
Enable the "Disable Automatic IAM Grants for Default Service Accounts" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command or through the Google Cloud Console.

