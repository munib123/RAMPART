# Vulnerability: HubPages User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hubpages.yaml`)

## Description
HubPages user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hubpages.com/@{{user}}
```

