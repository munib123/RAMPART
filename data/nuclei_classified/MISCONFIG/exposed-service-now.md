# Vulnerability: ITMS-Misconfigured
**Classification:** MISCONFIG
**Source:** Nuclei Template (`exposed-service-now.yaml`)

## Description
Detection of misconfigured ServiceNow ITSM instances.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/kb_view_customer.do?sysparm_article=KB00xxxx
```

