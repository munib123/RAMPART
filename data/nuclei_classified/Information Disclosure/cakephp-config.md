# Nuclei Template: CakePHP Configuration File - Detect
**Template ID:** cakephp-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`cakephp-config.yaml`)

## Vulnerability Information & PoC

## Description
CakePHP configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/phinx.yml
GET {{BaseURL}}/phinx.yaml
```

## References
- https://book.cakephp.org/phinx/0/en/configuration.html
