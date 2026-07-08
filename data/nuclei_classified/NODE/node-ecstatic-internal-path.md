# Vulnerability: Node ecstatic Internal Path - Exposure
**Classification:** NODE
**Source:** Nuclei Template (`node-ecstatic-internal-path.yaml`)

## Description
Internal path exposure in Node ecstatic.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{payload}}
```

