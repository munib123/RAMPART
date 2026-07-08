# Vulnerability: Abstract Api VAT Validation Rates Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-vat-validation-rates.yaml`)

## Description
Stay compliant with our simple, reliable, and powerful API for all your domestic and cross-border sales.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://vat.abstractapi.com/v1/?api_key={{token}}&vat_number=SE556656688001
```

