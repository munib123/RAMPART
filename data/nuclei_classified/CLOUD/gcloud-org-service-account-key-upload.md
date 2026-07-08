# Vulnerability: Service Account Key Upload Not Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-service-account-key-upload.yaml`)

## Description
Ensure that user-managed service account key upload is disabled within your Google Cloud project, folder, or the entire organization, through the "Disable Service Account Key Upload" organization policy. This allows you to control the upload process of unmanaged long-term credentials for your Cloud IAM service accounts. By default, users can upload keys to service accounts based on their Cloud IAM roles and permissions.

## Secure Mitigation
Enable the "Disable Service Account Key Upload" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the iam.disableServiceAccountKeyUpload constraint.

