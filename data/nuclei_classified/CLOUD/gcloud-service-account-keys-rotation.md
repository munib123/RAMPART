# Vulnerability: GCP Service Account Keys - No Rotation Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-service-account-keys-rotation.yaml`)

## Description
Detects Google Cloud Platform (GCP) service account keys that have no rotation enabled.
Keys with an expiration date of 9999-12-31T23:59:59 are considered non-rotating and pose security risks if compromised.

## Secure Mitigation
Implement a key rotation policy for user-managed service account keys. Regularly rotate keys and delete old ones. Consider using Workload Identity Federation to eliminate the need for long-lived keys entirely.

