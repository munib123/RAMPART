# Vulnerability: RDS Event Notification Absence
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-event-notify.yaml`)

## Description
Checks for the activation of event notifications for Amazon RDS instances to monitor significant database events.

## Secure Mitigation
Enable event notifications in Amazon RDS by creating an event subscription with Amazon SNS to receive notifications.

