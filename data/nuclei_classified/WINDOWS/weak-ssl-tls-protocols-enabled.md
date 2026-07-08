# Vulnerability: Weak SSL/TLS Protocols Enabled
**Classification:** WINDOWS
**Source:** Nuclei Template (`weak-ssl-tls-protocols-enabled.yaml`)

## Description
Checks if weak SSL/TLS protocols (such as SSLv2 or SSLv3) are enabled on the system.

## Secure Mitigation
Disable weak SSL/TLS protocols like SSLv2 and SSLv3 and enforce the use of stronger versions such as TLS 1.2 or higher.

