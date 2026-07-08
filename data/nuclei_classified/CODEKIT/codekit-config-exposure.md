# Vulnerability: CodeKit Configuration Exposure
**Classification:** CODEKIT
**Source:** Nuclei Template (`codekit-config-exposure.yaml`)

## Description
Detected exposed CodeKit configuration files that may have revealed sensitive project information, including file paths, build settings, hooks, and project structure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config.codekit3
GET {{BaseURL}}/config.codekit
GET {{BaseURL}}/assets/js/config.codekit3
```

