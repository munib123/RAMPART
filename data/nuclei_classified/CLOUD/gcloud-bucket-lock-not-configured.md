# Vulnerability: Configure Retention Policies with Bucket Lock for Log Buckets
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-bucket-lock-not-configured.yaml`)

## Description
Ensure that all retention policies attached to your Google Cloud log sink buckets are configured with the Bucket Lock feature. This prevents logging data from being overwritten or deleted and ensures compliance with data retention policies by locking the retention configuration.

## Secure Mitigation
Enable Bucket Lock on your Google Cloud log sink buckets to enforce retention policies and prevent changes to the data retention duration.

