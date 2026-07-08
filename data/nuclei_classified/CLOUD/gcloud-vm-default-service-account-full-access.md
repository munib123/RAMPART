# Vulnerability: VM Instance Using Default Service Account with Full API Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-default-service-account-full-access.yaml`)

## Description
Ensure that your Google Compute Engine instances are not configured to use the default service account with the Cloud API access scope set to "Allow full access to all Cloud APIs". The principle of least privilege (POLP), also known as the principle of least authority, is the security concept of giving the user/system/service the minimal set of permissions required to successfully perform its tasks.

## Secure Mitigation
Either replace the default service account with a custom one having minimal permissions, or change the access scope to "Allow default access" or "Set access for each API" with only required permissions.

