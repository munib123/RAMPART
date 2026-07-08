# Vulnerability: CloudFormation Stack Notification - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`stack-notification-disabled.yaml`)

## Description
Ensure that your Amazon CloudFormation stacks are using SNS topics to send notifications when important events occur.

## Secure Mitigation
Enable CloudFormation Stack Notifications by configuring SNS (Simple Notification Service) topics for your CloudFormation stack. This will ensure real-time alerts on stack events, including updates, errors, and resource creation, providing better monitoring and visibility.

