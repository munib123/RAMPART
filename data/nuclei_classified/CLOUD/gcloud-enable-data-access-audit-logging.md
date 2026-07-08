# Vulnerability: Enable Data Access Audit Logging for All Critical Service APIs
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-enable-data-access-audit-logging.yaml`)

## Description
Ensure that data access audit logging is enabled for all critical service APIs in your Google Cloud project for security, compliance, and troubleshooting purposes. The critical service APIs that you can enable for your GCP project include but are not limited to Identity and Access Management (IAM) API (iam.googleapis.com), Compute Engine API (compute.googleapis.com), Cloud Storage (storage-component.googleapis.com), Google Cloud Pub/Sub API (pubsub.googleapis.com), Cloud Key Management Service (KMS) API (cloudkms.googleapis.com), and Cloud Logging API (logging.googleapis.com).

## Secure Mitigation
Configure the IAM policy of your Google Cloud project to include the "auditConfigs" configuration object that enables data access audit logging for all critical APIs.

