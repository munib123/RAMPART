# Vulnerability: Service Account Key Creation Not Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-service-account-key-creation.yaml`)

## Description
Ensure that the creation of user-managed service account keys is disabled within your Google Cloud project, folder, or the entire organization through the "Disable Service Account Key Creation" organization policy. This allows you to control the use of unmanaged long-term credentials for your Cloud IAM service accounts. When this resource constraint is enabled, user-managed keys cannot be created for service accounts in projects/folders/organizations affected by the constraint.

## Secure Mitigation
Enable the "Disable Service Account Key Creation" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the iam.disableServiceAccountKeyCreation constraint.

