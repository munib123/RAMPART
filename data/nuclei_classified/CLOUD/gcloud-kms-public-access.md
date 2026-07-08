# Vulnerability: Publicly Accessible Google Cloud KMS Keys
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-kms-public-access.yaml`)

## Description
Ensure that the IAM policy associated with your Google Cloud Key Management Service (KMS) keys restricts anonymous and/or public access. The KMS cryptographic keys are controlled by Cloud IAM policies, which should not include bindings for "allUsers" and "allAuthenticatedUsers" to prevent public internet access.

## Secure Mitigation
Update the IAM policy for your KMS keys by removing any bindings that include "allUsers" or "allAuthenticatedUsers" to restrict access to authenticated and authorized users only.

