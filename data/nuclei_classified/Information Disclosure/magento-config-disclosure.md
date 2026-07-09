# Nuclei Template: Magento Configuration Panel - Detect
**Template ID:** magento-config-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`magento-config-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Magento configuration panel was detected. Misconfigured instances of Magento may disclose usernames, passwords, and database configurations via /app/etc/local.xml.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/app/etc/local.xml
GET {{BaseURL}}/app/etc/local.xml.additional
GET {{BaseURL}}/store/app/etc/local.xml
```

## References
- https://github.com/ptonewreckin/cmsDetector/blob/master/signatures/magento.py
