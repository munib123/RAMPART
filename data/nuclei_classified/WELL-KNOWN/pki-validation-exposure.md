# Vulnerability: Well-Known PKI Validation Directory
**Classification:** WELL-KNOWN
**Source:** Nuclei Template (`pki-validation-exposure.yaml`)

## Description
Detects CA/B Forum PKI validation artefacts directory.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/pki-validation/
GET {{BaseURL}}/well-known/pki-validation/
```

