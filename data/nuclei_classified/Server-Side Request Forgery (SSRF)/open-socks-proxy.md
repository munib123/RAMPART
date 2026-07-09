# Nuclei Template: Open SOCKS4/SOCKS5 proxy
**Template ID:** open-socks-proxy
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Medium
**CWE:** CWE-441
**Source:** Nuclei Template (`open-socks-proxy.yaml`)

## Vulnerability Information & PoC

## Description
The host accepts unauthenticated SOCKS4/SOCKS5 connections and can proxy TCP traffic to external destinations. This could allow abuse for anonymization, spam, scanning, or network pivoting. Verification was performed by successfully connecting to 1.1.1.1:80 through the proxy.

## References
- https://www.rfc-editor.org/rfc/rfc1928
- https://en.wikipedia.org/wiki/Open_proxy
- https://owasp.org/www-community/vulnerabilities/Unrestricted_Proxy
