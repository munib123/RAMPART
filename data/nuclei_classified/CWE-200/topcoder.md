# Vulnerability: Topcoder User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`topcoder.yaml`)

## Description
Topcoder user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://profiles.topcoder.com/{{user}}/
```

