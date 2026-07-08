# Vulnerability: Critical Service APIs Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-critical-service-apis-disabled.yaml`)

## Description
Ensure that critical service APIs are enabled for your GCP projects to gain access to essential functionalities and services provided by Google Cloud Platform (GCP), manage your project resources efficiently, enhance the security of your cloud environment, and track your usage and billing. The critical service APIs include, but are not limited to, Identity and Access Management (IAM) API, Compute Engine API, Cloud Storage, Google Cloud Pub/Sub API, Cloud Key Management Service (KMS) API, and Cloud Logging API.

## Secure Mitigation
Enable the necessary service APIs via the GCP Console or the gcloud command-line tool for each project where they are found to be disabled.

