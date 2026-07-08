# Vulnerability: Use Google-Managed SSL Certificates for Application Load Balancers
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-alb-ssl-google-managed.yaml`)

## Description
Ensure that your external Application Load Balancers (ALBs) are configured to use Google-managed SSL certificates instead of self-signed certificates in order to avoid triggering browser warnings and adding distrust for users visiting your site.

## Secure Mitigation
Configure your Application Load Balancers to use Google-managed SSL certificates to ensure trust and proper security standards.

