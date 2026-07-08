# Vulnerability: Backend Buckets Referencing Missing Storage Buckets
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-backend-bucket-missing-storage.yaml`)

## Description
Ensure that your Cloud CDN backend buckets are referencing existing storage buckets in order to be able to deliver static content efficiently from the nearest edge location to users, reducing latency and improving performance.

## Secure Mitigation
Verify that each backend bucket is referencing an existing storage bucket. Update the Cloud CDN backend bucket configuration to point to valid and existing storage buckets.

