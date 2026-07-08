# Vulnerability: Orbeon Forms Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`orbeon-forms-exposure.yaml`)

## Description
Detects exposed Orbeon Forms interfaces including Form Runner, Form Builder, and Quick Links. Orbeon Forms is a web forms solution that may expose sensitive form data and administrative interfaces if not properly secured.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/orbeon/
GET {{BaseURL}}
```

