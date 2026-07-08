# Vulnerability: Credentials Disclosure Check
**Classification:** CWE-522
**Source:** Nuclei Template (`credentials-disclosure.yaml`)

## Description
Look for keys/tokens/passwords in HTTP responses, exposed keys/tokens/secrets requires manual verification for impact evaluation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

