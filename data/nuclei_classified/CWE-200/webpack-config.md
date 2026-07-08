# Vulnerability: Webpack Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`webpack-config.yaml`)

## Description
Webpack configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webpack.config.js
```

