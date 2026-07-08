# Vulnerability: Disbale Nginx Server Tokens
**Classification:** AUDIT
**Source:** Nuclei Template (`file-disable-nginx-server-tokens.yaml`)

## Description
Detects if 'server_tokens' is enabled in Nginx, which can reveal version information.

## Secure Mitigation
Set 'server_tokens off;' in /etc/nginx/nginx.conf and restart Nginx.

