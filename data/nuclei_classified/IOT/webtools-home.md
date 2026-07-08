# Vulnerability: Webtools Home
**Classification:** IOT
**Source:** Nuclei Template (`webtools-home.yaml`)

## Description
Webtools panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wt2parser.cgi?home_en
```

