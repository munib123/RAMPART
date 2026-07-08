# Vulnerability: Missing API Key API Restrictions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-api-key-restrictions-missing.yaml`)

## Description
Ensure that the usage of your Google Cloud API keys is restricted to specific APIs such as Cloud Key Management Service (KMS) API, Cloud Storage API, Cloud Monitoring API, and Cloud Logging API. All Google Cloud API keys that are being used for production applications should use API restrictions.

## Secure Mitigation
Apply API restrictions to each Google Cloud API key to limit their usage to specific APIs. This can be managed through the Google Cloud Console or using the gcloud command-line tool.

