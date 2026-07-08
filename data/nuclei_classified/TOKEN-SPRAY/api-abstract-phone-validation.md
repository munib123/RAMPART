# Vulnerability: Abstract Api Phone Validation Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-phone-validation.yaml`)

## Description
Improve your contact rate and clean your lists with Abstract's industry-leading phone number validation API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://phonevalidation.abstractapi.com/v1/?api_key={{token}}&number=14154582468
```

