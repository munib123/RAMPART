# Vulnerability: Slides User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`slides.yaml`)

## Description
Slides user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://slides.com/{{user}}
```

