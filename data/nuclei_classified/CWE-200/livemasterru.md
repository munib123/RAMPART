# Vulnerability: Livemaster.ru User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`livemasterru.yaml`)

## Description
Livemaster.ru user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.livemaster.ru/{{user}}
```

