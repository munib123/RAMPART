# Vulnerability: Jolokia write to RCE valve
**Classification:** JOLOKIA
**Source:** Nuclei Template (`jolokia-acceslogvalve-rce.yaml`)

## Description
RCE in Jolokia < 1.7.1 using AccesLogValve

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jolokia/list
```

