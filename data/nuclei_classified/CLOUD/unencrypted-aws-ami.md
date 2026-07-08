# Vulnerability: Unencrypted AWS AMI
**Classification:** CLOUD
**Source:** Nuclei Template (`unencrypted-aws-ami.yaml`)

## Description
Ensure Amazon Machine Images (AMIs) are encrypted to meet data-at-rest encryption compliance and protect sensitive data.

## Secure Mitigation
Encrypt your AMIs using AWS managed keys or customer-managed keys in the AWS Key Management Service (KMS) to ensure data security.

