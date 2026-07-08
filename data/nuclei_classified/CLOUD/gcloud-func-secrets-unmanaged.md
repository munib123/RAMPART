# Vulnerability: Use Secrets Manager for Managing Secrets in Google Cloud Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-func-secrets-unmanaged.yaml`)

## Description
To prevent unauthorized access or accidental exposure of sensitive information, ensure that Secrets Manager service is used to store and manage secrets instead of storing them in cleartext within Cloud Functions environment variables.

## Secure Mitigation
Refactor your Google Cloud Functions to use Secrets Manager for managing sensitive configuration settings instead of storing them directly in environment variables.

