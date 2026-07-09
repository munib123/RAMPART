# Nuclei Template: 3CX Config - File Disclosure
**Template ID:** 3cx-config
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-219
**Source:** Nuclei Template (`3cx-config.yaml`)

## Vulnerability Information & PoC

## Description
3CX Configuration file was discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/SetupConfig.xml
```

## References
- https://www.3cx.com/docs/configure-pbx-automatically/
