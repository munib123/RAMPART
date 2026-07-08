# Vulnerability: User-Managed Service Account Keys Found
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-service-account-user-keys.yaml`)

## Description
Ensure that your Google Cloud Platform (GCP) user-managed service accounts are using GCP-managed keys instead of user-managed keys for authentication. For user-managed key pairs, key management operations such as key storage, key distribution, key revocation, key recovery, and key rotation, as well as key protection against unauthorized access, are your responsibilities.

## Secure Mitigation
Transition to using GCP-managed keys for service accounts to ensure key management is handled by Google Cloud, thereby enhancing security and reducing the administrative burden of manual key management.

