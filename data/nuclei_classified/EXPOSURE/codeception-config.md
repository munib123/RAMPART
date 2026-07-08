# Vulnerability: Codeception YAML Configuration File - Detect
**Classification:** EXPOSURE
**Source:** Nuclei Template (`codeception-config.yaml`)

## Description
Codeception YAML configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/codeception.yml
```

