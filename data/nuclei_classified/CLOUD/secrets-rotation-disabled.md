# Vulnerability: Secret Rotation Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`secrets-rotation-disabled.yaml`)

## Description
Ensure that AWS Secrets Manager service is configured to automatically rotate your service or database secrets (i.e. enable automatic rotation feature for your secrets).

## Secure Mitigation
Enable automatic secret rotation in AWS Secrets Manager by configuring a rotation schedule and associating a Lambda function to periodically update and securely rotate the secrets.

