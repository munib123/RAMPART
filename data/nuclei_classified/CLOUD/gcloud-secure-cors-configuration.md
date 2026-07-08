# Vulnerability: Secure CORS Configuration for Cloud Storage Buckets
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-secure-cors-configuration.yaml`)

## Description
Ensure that Cross-Origin Resource Sharing (CORS) configuration set for your Google Cloud Storage buckets only allows trusted origins to prevent unauthorized data access from web applications. The trusted, authorized origins must be configured according to your organization's policy.

## Secure Mitigation
Update the CORS configuration for your Cloud Storage buckets to only allow trusted origins defined by your organization’s policy.

