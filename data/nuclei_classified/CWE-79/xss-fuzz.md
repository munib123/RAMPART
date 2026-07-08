# Vulnerability: Fuzzing Parameters - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`xss-fuzz.yaml`)

## Description
Cross-site scripting was discovered via a search for reflected parameter values in the server response via GET-requests.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?{{xss_param}}
```

