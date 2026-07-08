# Vulnerability: Quest Modem Configuration Login - Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`quest-panel.yaml`)

## Description
Quest Modem Configuration login Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/webcm?getpage=../html/login.html
```

