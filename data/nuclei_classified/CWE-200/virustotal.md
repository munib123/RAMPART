# Vulnerability: Virustotal User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`virustotal.yaml`)

## Description
Virustotal user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.virustotal.com/gui/user/{{user}}
```

