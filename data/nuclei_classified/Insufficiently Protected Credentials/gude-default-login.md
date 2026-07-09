# Nuclei Template: GUDE - Default Login
**Template ID:** gude-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`gude-default-login.yaml`)

## Vulnerability Information & PoC

## Description
GUDE 2301 and 2302 default administrator login credentials (admin:admin) were detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ov.html?
```

## References
- https://media.distrelec.com/Web/Downloads/_m/an/Gude_2302-1_ger_man.pdf
