# Vulnerability: Magento Version Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`magento-version-detect.yaml`)

## Description
Magento version detection via version module and copyright text.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /magento_version HTTP/1.1
Host: {{Hostname}}

GET /skin/frontend/default/default/css/styles.css HTTP/1.1
Host: {{Hostname}}
```

