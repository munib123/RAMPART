# Vulnerability: Magento Configuration Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`magento-config-disclosure.yaml`)

## Description
Magento configuration panel was detected. Misconfigured instances of Magento may disclose usernames, passwords, and database configurations via /app/etc/local.xml.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/app/etc/local.xml
GET {{BaseURL}}/app/etc/local.xml.additional
GET {{BaseURL}}/store/app/etc/local.xml
```

