# Vulnerability: Azure VM Disk Volumes BYOK Encryption Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-byok-disk-volumes-not-enabled.yaml`)

## Description
Ensure that your Azure virtual machine disk volumes are using customer-managed keys (also known as Bring Your Own Keys - BYOKs) instead of service-managed keys (default keys used by Microsoft Azure for disk encryption), in order to have a more granular control over your VM data encryption/decryption process.

## Secure Mitigation
Configure your VM disk volumes to use customer-managed keys (BYOK) to ensure better security and control over your data encryption and decryption processes.

