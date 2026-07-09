# Nuclei Template: Coveralls Configuration File Exposure
**Template ID:** coveralls-configuration-file-exposure
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** Medium
**CWE:** CWE-538
**Source:** Nuclei Template (`coveralls-configuration-file-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected a Coveralls configuration file (.coveralls.yml) on the target. This file could have exposed a sensitive repo_token, allowing an attacker to submit fake data, view private coverage details, or impersonate the project.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.coveralls.yml
```

## References
- https://docs.coveralls.io/ci-services
- https://coveralls-python.readthedocs.io/en/latest/usage/configuration.html
