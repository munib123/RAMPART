# Vulnerability: Google Cloud Functions Using Default Service Account
**Classification:** CLOUD
**Source:** Nuclei Template (`gcp-func-default-svc-acc.yaml`)

## Description
Ensure that your Google Cloud functions are configured to use user-managed service accounts instead of the default service account managed by Google Cloud in order to follow the Principle of Least Privilege (POLP) and enhance the security posture of your functions.

## Secure Mitigation
Configure your Google Cloud functions to use user-managed service accounts that have only the permissions necessary for the function to operate.

