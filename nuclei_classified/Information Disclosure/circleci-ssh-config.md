# Nuclei Template: CircleCI SSH Configuration - Detect
**Template ID:** circleci-ssh-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`circleci-ssh-config.yaml`)

## Vulnerability Information & PoC

## Description
CircleCI ssh-config file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.circleci/ssh-config
```

