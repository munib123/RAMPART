# Vulnerability: Ultras Diary User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ultras-diary.yaml`)

## Description
Ultras Diary user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://ultrasdiary.pl/u/{{user}}/
```

