# Vulnerability: Insufficient Log Data Retention Period in Cloud Logging Buckets
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-log-retention-period-insufficient.yaml`)

## Description
For security, reliability, and compliance purposes, ensure that your Cloud Logging buckets are configured with a data retention period of 365 days or more. A Cloud Logging bucket is a container that stores log data from cloud services such as Compute Engine and App Engine. The retention period represents the number of days to retain log data for a user-defined log bucket and also for the _Default log bucket.

## Secure Mitigation
Update the retention period for your Cloud Logging buckets to 365 days or more using the Google Cloud CLI or the Console to ensure compliance with best practices.

