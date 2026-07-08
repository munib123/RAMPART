# Vulnerability: Automatic Storage Increase Disabled for Google Cloud SQL Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-auto-storage-disabled.yaml`)

## Description
Ensure that the Automatic Storage Increase feature is enabled for your production Google Cloud SQL database instances. This feature prevents database servers from running out of storage space and becoming read-only, disrupting normal operations. When a database instance runs out of available space, it can drop existing connections and cause downtime, potentially violating the Google Cloud SQL Service Level Agreement (SLA).

## Secure Mitigation
Enable the Automatic Storage Increase feature for your Google Cloud SQL database instances to prevent storage exhaustion and ensure uninterrupted operations.

