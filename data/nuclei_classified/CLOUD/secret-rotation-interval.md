# Vulnerability: Secret Rotation Interval
**Classification:** CLOUD
**Source:** Nuclei Template (`secret-rotation-interval.yaml`)

## Description
Ensure that the rotation interval for your AWS Secrets Manager secrets is configured to meet security and compliance requirements.

## Secure Mitigation
Enable automatic secret rotation in AWS by configuring AWS Secrets Manager with a defined rotation interval (e.g., every 30 days) and using Lambda functions to automate the rotation process, ensuring credentials are regularly updated and secure.

