# Vulnerability: CloudFront Compress Objects Automatically
**Classification:** CLOUD
**Source:** Nuclei Template (`cloudfront-compress-object.yaml`)

## Description
Ensure that your Amazon CloudFront Content Delivery Network (CDN) distributions are configured to automatically compress content for web requests that include "Accept-Encoding: gzip" in the request header, in order to increase the websites/web applications performance and reduce bandwidth costs.

## Secure Mitigation
Enable "Compress Objects Automatically" in CloudFront to reduce data transfer sizes, enhance loading speeds, and improve overall performance for end users.

