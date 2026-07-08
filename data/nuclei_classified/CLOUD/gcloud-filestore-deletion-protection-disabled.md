# Vulnerability: Filestore Instance Deletion Protection Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-filestore-deletion-protection-disabled.yaml`)

## Description
Ensure that your Google Cloud Filestore instances have Deletion Protection feature enabled in order to protect them from being accidentally deleted. With the Deletion Protection safety feature enabled, your Filestore instances are guaranteed to be protected from accidental deletion, ensuring your data remains safe.

## Secure Mitigation
Enable deletion protection for your Filestore instances using the 'gcloud filestore instances update' command with the '--deletion-protection' flag or through the Google Cloud Console.

