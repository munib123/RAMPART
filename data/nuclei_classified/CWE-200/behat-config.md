# Vulnerability: Behat Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`behat-config.yaml`)

## Description
Behat configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/behat.yml
GET {{BaseURL}}/behat.yml.dist
```

