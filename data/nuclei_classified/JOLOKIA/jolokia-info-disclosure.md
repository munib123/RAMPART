# Vulnerability: Jolokia - Information disclosure
**Classification:** JOLOKIA
**Source:** Nuclei Template (`jolokia-info-disclosure.yaml`)

## Description
Jolokia - Information is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{jolokia_paths}}{{mbean_paths}}
```

