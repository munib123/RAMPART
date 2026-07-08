# Vulnerability: EBS Encryption - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`ebs-encryption-disabled.yaml`)

## Description
Ensure that all your Amazon Elastic Block Store (EBS) volumes are encrypted in order to meet security and compliance requirements. With encryption enabled, your EBS volumes can hold sensitive, confidential, and critical data.

## Secure Mitigation
Enable encryption for all existing EBS volumes and ensure that all new volumes created are configured to use encryption by default. Additionally, update any snapshots to be encrypted and use AWS Key Management Service (KMS) to manage encryption keys securely.

