# Vulnerability: Delete Google Cloud API Keys
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-api-keys-present.yaml`)

## Description
Ensure that all your Google Cloud projects are using standard authentication flow instead of API keys for authentication. Google Cloud Platform (GCP) API keys are simple encrypted strings that can be used when calling certain APIs which don't need to access private user data. GCP API keys are usually accessible to clients, as they can be publicly viewed from within a browser, making it easy to discover and steal an API key.

## Secure Mitigation
Remove all API keys and replace them with standard authentication methods to secure your applications.

