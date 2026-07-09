# Nuclei Template: Symfony Database Configuration File - Detect
**Template ID:** symfony-database-config
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`symfony-database-config.yaml`)

## Vulnerability Information & PoC

## Description
Symfony database configuration file was detected and may contain database credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/config/databases.yml
```

## References
- https://symfony.com/legacy/doc/reference/1_3/en/07-Databases
