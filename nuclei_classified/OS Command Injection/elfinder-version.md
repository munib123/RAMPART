# Nuclei Template: elFinder 2.1.58 - Remote Code Execution
**Template ID:** elfinder-version
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`elfinder-version.yaml`)

## Vulnerability Information & PoC

## Description
elFinder 2.1.58 is vulnerable to remote code execution. This can allow an attacker to execute arbitrary code and commands on the server hosting the elFinder PHP connector, even with minimal configuration.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/js/elfinder.min.js
GET {{BaseURL}}/js/elFinder.version.js
```

## Remediation
The issues were patched in version 2.1.59. As a workaround, ensure the connector is not exposed without authentication.

## References
- https://github.com/Studio-42/elFinder/
