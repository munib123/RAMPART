# Nuclei Template: Behat Configuration File - Detect
**Template ID:** behat-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`behat-config.yaml`)

## Vulnerability Information & PoC

## Description
Behat configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/behat.yml
GET {{BaseURL}}/behat.yml.dist
```

## References
- https://docs.behat.org/en/v2.5/guides/7.config.html
