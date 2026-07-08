# Vulnerability: PCPartPicker User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pcpartpicker.yaml`)

## Description
PCPartPicker user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pcpartpicker.com/user/{{user}}/
```

