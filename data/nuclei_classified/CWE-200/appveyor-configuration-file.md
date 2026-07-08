# Vulnerability: AppVeyor Configuration Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`appveyor-configuration-file.yaml`)

## Description
AppVeyor configuration page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.appveyor.yml
GET {{BaseURL}}/appveyor.yml
```

