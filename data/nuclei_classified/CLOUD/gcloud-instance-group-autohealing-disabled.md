# Vulnerability: Instance Group Autohealing Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-instance-group-autohealing-disabled.yaml`)

## Description
Ensure that your Google Cloud Managed Instance Groups (MIGs) are configured with Autohealing feature. Autohealing allows re-creating virtual machine instances when they become unresponsive. Application-based autohealing improves application availability by relying on a health checking signal that detects application-specific issues such as freezing, crashing, or overloading.

## Secure Mitigation
Enable autohealing for your Managed Instance Groups by configuring a health check that monitors instance health. Configure appropriate check intervals, timeouts, and healthy/unhealthy thresholds based on your application requirements.

