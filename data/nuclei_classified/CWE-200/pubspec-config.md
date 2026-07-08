# Vulnerability: Pubspec YAML Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pubspec-config.yaml`)

## Description
Pubspec YAML configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pubspec.yaml
GET {{BaseURL}}/assets/pubspec.yaml
```

