# Nuclei Template: Redmine Configuration File - Detect
**Template ID:** redmine-config
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`redmine-config.yaml`)

## Vulnerability Information & PoC

## Description
Redmine configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/configuration.yml
GET {{BaseURL}}/config/configuration.yml
GET {{BaseURL}}/redmine/config/configuration.yml
```

## References
- https://www.exploit-db.com/ghdb/5803
