# Nuclei Template: Open Redirect - Detection
**Template ID:** open-redirect-generic
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`open-redirect-generic.yaml`)

## Vulnerability Information & PoC

## Description
An open redirect vulnerability was detected. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{RootURL}}/{{redirect}}
```

