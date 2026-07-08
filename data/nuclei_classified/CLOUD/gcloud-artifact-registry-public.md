# Vulnerability: Publicly Accessible Artifact Registry Repositories
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-artifact-registry-public.yaml`)

## Description
Identify any publicly accessible Artifact Registry repositories within your Google Cloud account and update their IAM policy in order to protect against unauthorized access. To deny access from anonymous and public users, remove the bindings for "allUsers" and "allAuthenticatedUsers" members from the IAM policy associated with your repository.

## Secure Mitigation
Update the IAM policies for each Artifact Registry repository to remove "allUsers" and "allAuthenticatedUsers". This action will ensure that repositories are not exposed to any user on the internet or authenticated users not explicitly granted permission.

