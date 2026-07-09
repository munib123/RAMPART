# Nuclei Template: Integrated Management Module - Default Login
**Template ID:** imm-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`imm-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Integrated Management Module default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/data/login
```

## References
- https://pubs.lenovo.com/x3650-m4/t_logging_web_interface
- https://www.ibm.com/docs/en/tcs-service?topic=oip-logging-imm-web-interface
