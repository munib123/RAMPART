# Vulnerability: Jolokia - Searching MBeans
**Classification:** JOLOKIA
**Source:** Nuclei Template (`jolokia-mbean-search.yaml`)

## Description
Unauth users can search Mbeans in Jolokia.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jolokia/search/*:test=test
GET {{BaseURL}}/actuator/jolokia/search/*:test=test
```

