# Vulnerability: CodeClimate Configuration File - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`codeclimate-config-exposure.yaml`)

## Description
Detected CodeClimate configuration file, exposing code quality settings and excluded paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.codeclimate.yml
```

