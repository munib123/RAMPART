# Vulnerability: Deprecated TLS Detection
**Classification:** SSL
**Source:** Nuclei Template (`deprecated-tls.yaml`)

## Description
Both TLS 1.1 and SSLv3 are deprecated in favor of stronger encryption.

## Secure Mitigation
Update the web server's TLS configuration to disable TLS 1.1 and SSLv3.

