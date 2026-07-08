# Vulnerability: Crowdin User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`crowdin.yaml`)

## Description
Crowdin user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://crowdin.com/profile/{{user}}
```

