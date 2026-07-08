# Vulnerability: Cloudfront Logging Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`cloudfront-logging-disabled.yaml`)

## Description
Ensure that access (standard) logging is enabled for your Amazon CloudFront distributions in order to track all viewer requests for the web content delivered through the Content Delivery Network (CDN).

## Secure Mitigation
Enable encryption for all existing EBS volumes and ensure that all new volumes created are configured to use encryption by default. Additionally, update any snapshots to be encrypted and use AWS Key Management Service (KMS) to manage encryption keys securely.

