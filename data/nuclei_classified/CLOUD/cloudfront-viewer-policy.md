# Vulnerability: CloudFront Viewer Protocol Policy
**Classification:** CLOUD
**Source:** Nuclei Template (`cloudfront-viewer-policy.yaml`)

## Description
Ensure that the communication between your Amazon CloudFront distribution and its viewers is encrypted using HTTPS in order to secure the delivery of your web content.

## Secure Mitigation
Configure your Amazon CloudFront distribution's viewer protocol policy to either redirect HTTP requests to HTTPS or require HTTPS connections exclusively, ensuring secure delivery of web content and protecting against potential data breaches.

