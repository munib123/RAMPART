# Vulnerability: Publicly Accessible Google Cloud Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-func-public-access.yaml`)

## Description
Identify any publicly accessible Google Cloud functions within your GCP account and update their IAM policy to protect against unauthorized users sending requests to invoke these functions. To deny access from anonymous and public users, remove the bindings for allUsers and allAuthenticatedUsers members from your function's IAM policy. The allUsers member represents any user on the Internet, while allAuthenticatedUsers represents any user or service account that can sign into Google Cloud Platform (GCP) with a Google account.

## Secure Mitigation
Update the IAM policies of your Google Cloud functions to remove allUsers and allAuthenticatedUsers from the bindings to ensure that the functions are not publicly accessible.

