# Vulnerability: Inactive Service Accounts in Google Cloud Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-func-inactive-svc-acc.yaml`)

## Description
Ensure that your Google Cloud functions are referencing existing, active service accounts in order to prevent execution failures and operational disruptions.

## Secure Mitigation
Verify and update the service accounts associated with your Google Cloud functions to ensure they are active and have the necessary permissions for function execution.

