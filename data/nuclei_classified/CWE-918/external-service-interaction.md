# Vulnerability: External Service Interaction
**Classification:** CWE-918
**Source:** Nuclei Template (`external-service-interaction.yaml`)

## Description
External Service interaction via Host Header Injection.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

