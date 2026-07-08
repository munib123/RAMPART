# Vulnerability: Virtual Machine Disk Encryption with Customer-Supplied Keys Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-disk-csek-not-enabled.yaml`)

## Description
Ensure that the disks attached to your production Google Compute Engine instances are encrypted with Customer-Supplied Encryption Keys (CSEKs) in order to have complete control over the data-at-rest encryption and decryption process. CSEKs allow you to provide your own encryption keys that Google Compute Engine uses to protect the Google-generated keys used to encrypt and decrypt your instance data.

## Secure Mitigation
Re-create your VM instances with Customer-Supplied Encryption Keys (CSEKs) by providing a 256-bit string encoded in RFC 4648 standard base64 during instance creation. Note that Compute Engine does not store your CSEKs on its servers and cannot access your protected data unless you provide the required key.

