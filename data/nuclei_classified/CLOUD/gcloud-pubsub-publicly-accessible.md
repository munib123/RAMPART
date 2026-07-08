# Vulnerability: Publicly Accessible Pub/Sub Topics
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pubsub-publicly-accessible.yaml`)

## Description
Identify any publicly accessible Pub/Sub topics within your Google Cloud account and update their IAM policy to prevent unauthorized access and sensitive data exposure. To achieve this, remove the bindings for "allUsers" and "allAuthenticatedUsers" members from your topic's IAM policy. "allUsers" is a special member identifier representing any user on the internet, including both authenticated and unauthenticated users. Similarly, "allAuthenticatedUsers" represents any user or service account that can sign in to Google Cloud Platform (GCP) with a Google account.

## Secure Mitigation
Remove "allUsers" and "allAuthenticatedUsers" from the IAM policy bindings of your Pub/Sub topics. This ensures only authorized identities have access to the topics.

