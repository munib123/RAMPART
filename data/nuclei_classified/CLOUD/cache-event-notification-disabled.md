# Vulnerability: ElastiCache Event Notifications - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`cache-event-notification-disabled.yaml`)

## Description
Ensure that your Amazon ElastiCache clusters are configured to send event notifications via Amazon Simple Notification Service (SNS) in order to monitor your cache clusters for important events and quickly mitigate any issues with your cache system.

## Secure Mitigation
To remediate the disabled ElastiCache event notifications, enable event notifications in the AWS Management Console by configuring an Amazon SNS topic to receive alerts for important cluster events.

