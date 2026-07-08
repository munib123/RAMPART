# Vulnerability: ReblogMe User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`reblogme.yaml`)

## Description
ReblogMe user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.reblogme.com
```

