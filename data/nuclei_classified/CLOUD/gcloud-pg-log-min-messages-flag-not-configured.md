# Vulnerability: Log Min Messages Flag Not Configured Properly for PostgreSQL Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pg-log-min-messages-flag-not-configured.yaml`)

## Description
Ensure that the "log_min_messages" database flag configured for your Google Cloud PostgreSQL database instances has the appropriate severity level in accordance with your organization's logging policy. The "log_min_messages" flag defines the minimum severity level for messages to be logged. Valid levels include DEBUG5, DEBUG4, DEBUG3, DEBUG2, DEBUG1, INFO, NOTICE, WARNING, ERROR, LOG, FATAL, and PANIC.

## Secure Mitigation
Set the "log_min_messages" flag to the appropriate severity level (e.g., ERROR) as per your organization's logging policy to balance logging effectiveness and performance.

