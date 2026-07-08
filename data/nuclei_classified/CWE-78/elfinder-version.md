# Vulnerability: elFinder 2.1.58 - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`elfinder-version.yaml`)

## Description
elFinder 2.1.58 is vulnerable to remote code execution. This can allow an attacker to execute arbitrary code and commands on the server hosting the elFinder PHP connector, even with minimal configuration.

## Secure Mitigation
The issues were patched in version 2.1.59. As a workaround, ensure the connector is not exposed without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/js/elfinder.min.js
GET {{BaseURL}}/js/elFinder.version.js
```

