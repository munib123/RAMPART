# Vulnerability: CloudWatch Alarms Actions Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`cw-alarms-actions.yaml`)

## Description
Ensure that all Amazon CloudWatch alarms have actions enabled (ActionEnabled: true) to respond to state changes.

## Secure Mitigation
Enable actions for each CloudWatch alarm by setting the ActionEnabled parameter to true, allowing for automated responses to alarms.

