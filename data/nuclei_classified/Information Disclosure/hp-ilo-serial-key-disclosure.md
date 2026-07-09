# Nuclei Template: HP iLO Serial Key - Detect
**Template ID:** hp-ilo-serial-key-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`hp-ilo-serial-key-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
HP iLO serial key was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/xmldata?item=CpqKey
```

## References
- https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/hp-ilo-serial-key-disclosure.json
