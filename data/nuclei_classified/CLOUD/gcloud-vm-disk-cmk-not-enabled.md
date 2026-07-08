# Vulnerability: Virtual Machine Disk Encryption with Customer-Managed Keys Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-disk-cmk-not-enabled.yaml`)

## Description
Ensure that the persistent disks attached to your Google Compute Engine instances are encrypted with Customer-Managed Keys (CMKs) in order to have a fine control over your sensitive data encryption and decryption process. You can create and manage your own Customer-Managed Keys (CMKs) with Cloud Key Management Service (Cloud KMS). Cloud KMS provides secure and efficient encryption key management, controlled key rotation, and revocation mechanisms.

## Secure Mitigation
Configure your Compute Engine persistent disks to use Customer-Managed Keys (CMKs) for encryption by specifying a Cloud KMS key during disk creation or by updating existing disks.

