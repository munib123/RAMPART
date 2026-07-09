# Nuclei Template: Fuzzing Parameters - Cross-Site Scripting
**Template ID:** xss-fuzz
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`xss-fuzz.yaml`)

## Vulnerability Information & PoC

## Description
Cross-site scripting was discovered via a search for reflected parameter values in the server response via GET-requests.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?{{xss_param}}
```

