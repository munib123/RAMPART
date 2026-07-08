# Vulnerability: VM Disk Encryption with Customer-Supplied Keys Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-disk-csek-disabled.yaml`)

## Description
Ensure that the disks attached to your production Google Compute Engine instances are encrypted with Customer-Supplied Encryption Keys (CSEKs) in order to have complete control over the data-at-rest encryption and decryption process, and meet strict compliance requirements.

## Secure Mitigation
Enable Customer-Supplied Encryption Keys (CSEKs) for your VM disks by providing a valid encryption key during disk creation or instance launch. The key must be a 256-bit string encoded in RFC 4648 base64 format.

