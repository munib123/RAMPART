# Vulnerability: MuleSoft DataWeave Interactive Learning Environment - Unauthenticated Access
**Classification:** CWE-94
**Source:** Nuclei Template (`unauth-mulesoft-dataweave.yaml`)

## Description
The MuleSoft DataWeave Interactive Learning Environment is publicly accessible without authentication

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

