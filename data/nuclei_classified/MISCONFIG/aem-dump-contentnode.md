# Vulnerability: AEM Dump Content Node Properties
**Classification:** MISCONFIG
**Source:** Nuclei Template (`aem-dump-contentnode.yaml`)

## Description
Node Properties are exposed in AEM Dump.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/content.infinity.json
GET {{BaseURL}}/{{path}}
```

