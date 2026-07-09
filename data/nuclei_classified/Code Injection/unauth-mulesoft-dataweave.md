# Nuclei Template: MuleSoft DataWeave Interactive Learning Environment - Unauthenticated Access
**Template ID:** unauth-mulesoft-dataweave
**Vulnerability Class:** Code Injection
**Severity:** High
**CWE:** CWE-94
**Source:** Nuclei Template (`unauth-mulesoft-dataweave.yaml`)

## Vulnerability Information & PoC

## Description
The MuleSoft DataWeave Interactive Learning Environment is publicly accessible without authentication

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
```

