# Vulnerability: Abstract Api Email Validation Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-email-validation.yaml`)

## Description
Improve your delivery rate and clean your email lists with Abstract's industry-leading email verification API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://emailvalidation.abstractapi.com/v1/?api_key={{token}}&email=johnsmith@gmail.com
```

