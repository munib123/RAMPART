# Vulnerability: Coveralls Configuration File Exposure
**Classification:** CWE-538
**Source:** Nuclei Template (`coveralls-configuration-file-exposure.yaml`)

## Description
Detected a Coveralls configuration file (.coveralls.yml) on the target. This file could have exposed a sensitive repo_token, allowing an attacker to submit fake data, view private coverage details, or impersonate the project.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.coveralls.yml
```

