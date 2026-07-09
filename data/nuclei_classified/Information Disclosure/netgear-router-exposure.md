# Nuclei Template: NETGEAR Routers - Serial Number Disclosure
**Template ID:** netgear-router-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`netgear-router-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Multiple NETGEAR router models disclose their serial number which can be used to obtain the admin password if password recovery is enabled.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/rootDesc.xml
```

## References
- https://www.exploit-db.com/exploits/47117
