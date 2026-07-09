# Nuclei Template: Apache Configuration File - Detect
**Template ID:** apache-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`apache-config.yaml`)

## Vulnerability Information & PoC

## Description
Apache configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/apache.conf
```

## Remediation
Remove the configuration file from the web root.

## References
- https://httpd.apache.org/docs/2.4/configuring.html
