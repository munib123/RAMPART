# Vulnerability: CakePHP Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cakephp-config.yaml`)

## Description
CakePHP configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phinx.yml
GET {{BaseURL}}/phinx.yaml
```

