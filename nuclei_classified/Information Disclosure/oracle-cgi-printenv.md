# Nuclei Template: Oracle CGI printenv - Information Disclosure
**Template ID:** oracle-cgi-printenv
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`oracle-cgi-printenv.yaml`)

## Vulnerability Information & PoC

## Description
Oracle CGI printenv component is susceptible to an information disclosure vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/printenv
```

## References
- https://github.com/ilmila/J2EEScan/blob/master/src/main/java/burp/j2ee/issues/impl/OracleCGIPrintEnv.java
