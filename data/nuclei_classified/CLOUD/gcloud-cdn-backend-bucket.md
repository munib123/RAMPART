# Vulnerability: Check Cloud CDN Backend Bucket Configuration
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-cdn-backend-bucket.yaml`)

## Description
Ensure that the Cloud CDN origin associated with your Google Cloud load balancer points to a backend bucket instead of a backend service in order to provide enhanced performance, cost savings, simplified management, and the ability to customize caching rules.

## Secure Mitigation
Reconfigure the Cloud CDN origin to point to a backend bucket instead of a backend service by modifying the associated Google Cloud load balancer's URL map.

