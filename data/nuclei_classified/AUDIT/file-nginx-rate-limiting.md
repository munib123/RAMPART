# Vulnerability: Missing Nginx Rate Limiting Configuration
**Classification:** AUDIT
**Source:** Nuclei Template (`file-nginx-rate-limiting.yaml`)

## Description
Ensures that rate limiting is properly configured in Nginx to prevent excessive requests from a single client.

## Secure Mitigation
Add 'limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;' in /etc/nginx/nginx.conf.

