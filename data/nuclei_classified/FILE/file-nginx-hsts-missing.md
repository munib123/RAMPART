# Vulnerability: Missing Nginx HSTS
**Classification:** FILE
**Source:** Nuclei Template (`file-nginx-hsts-missing.yaml`)

## Description
Ensures that HSTS (Strict-Transport-Security) is enabled in Nginx.

## Secure Mitigation
Add 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";' in /etc/nginx/nginx.conf under the server block.

