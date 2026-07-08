# Vulnerability: Pub/Sub Subscription Cross-Project Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pubsub-crossproject-access.yaml`)

## Description
Ensure that your Google Cloud Pub/Sub subscriptions are configured to allow access only to trusted GCP projects to protect against unauthorized cross-project access. The list with the trusted GCP projects must be defined in the conformity rule settings, in the Trend Cloud One™ – Conformity account console.

## Secure Mitigation
Restrict access to Pub/Sub subscriptions by configuring IAM policies to include only trusted service accounts or users. Ensure roles such as "roles/pubsub.subscriber", "roles/pubsub.editor", or "roles/pubsub.admin" are only assigned to trusted principals.

