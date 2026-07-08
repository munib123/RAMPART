# Vulnerability: Enable Data Access Audit Logs for Cloud Storage
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-data-access-audit-logs-not-enabled.yaml`)

## Description
Ensure that Data Access audit logs are enabled for your Google Cloud Storage buckets and objects to track read, write, and admin operations. Data Access audit logs provide insights into resource usage and help ensure security, compliance, and effective troubleshooting.

## Secure Mitigation
Enable Data Access audit logs for the "storage.googleapis.com" service in your project to monitor all read, write, and admin activities on Cloud Storage resources.

