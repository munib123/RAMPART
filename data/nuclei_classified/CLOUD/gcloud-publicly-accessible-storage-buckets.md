# Vulnerability: Check for Publicly Accessible Cloud Storage Buckets
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-publicly-accessible-storage-buckets.yaml`)

## Description
Ensure that the IAM policy associated with your Google Cloud Storage buckets is restricting anonymous and/or public access. The IAM policy should not include bindings for "allUsers" or "allAuthenticatedUsers" to prevent unauthorized access to sensitive data.

## Secure Mitigation
Update the IAM policy of your Google Cloud Storage buckets to remove bindings for "allUsers" and "allAuthenticatedUsers" members, restricting access to authorized users only.

