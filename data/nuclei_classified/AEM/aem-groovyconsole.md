# Vulnerability: AEM Groovy Console Discovery
**Classification:** AEM
**Source:** Nuclei Template (`aem-groovyconsole.yaml`)

## Description
An Adobe Experience Manager Groovy console was discovered. This can possibly lead to remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/groovyconsole
GET {{BaseURL}}/etc/groovyconsole.html
```

