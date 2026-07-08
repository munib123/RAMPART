# Vulnerability: OS Login with 2FA Authentication Not Enabled for VM Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-oslogin-2fa-disabled.yaml`)

## Description
Ensure that the OS Login feature enabled at the virtual machine instance level is configured with Two-Factor Authentication (2FA) in order to help protect the access to your Google Cloud VM instances. Two-Factor Authentication (also known as Multi-Factor Authentication - MFA) provides an additional layer of security on top of the existing credentials.

## Secure Mitigation
Enable OS Login with 2FA authentication for all VM instances by setting the "enable-oslogin-2fa" metadata key to "TRUE".

