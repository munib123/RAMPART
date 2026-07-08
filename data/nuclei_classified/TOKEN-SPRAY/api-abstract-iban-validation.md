# Vulnerability: Abstract Api IBAN Validation Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-iban-validation.yaml`)

## Description
A powerful REST API to validate IBAN quickly and securely

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ibanvalidation.abstractapi.com/v1/?api_key={{token}}&iban=BE71096123456769
```

