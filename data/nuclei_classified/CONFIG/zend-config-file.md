# Vulnerability: Zend Configuration File
**Classification:** CONFIG
**Source:** Nuclei Template (`zend-config-file.yaml`)

## Description
Zend configuration file was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

