# Vulnerability: Define Index Page Suffix and Error Page for Bucket Website Configuration
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-bucket-website-config-not-defined.yaml`)

## Description
Ensure that website index (main) page suffix and error (404 not found) page are defined for your Google Cloud Storage buckets with static website configuration. Specifying these configurations ensures proper functionality and user experience for websites hosted on Cloud Storage buckets.

## Secure Mitigation
Define an index page suffix (e.g., index.html) and an error page (e.g., 404.html) in the static website configuration for your Cloud Storage buckets.

