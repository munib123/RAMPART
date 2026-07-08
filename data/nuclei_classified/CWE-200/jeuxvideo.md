# Vulnerability: Jeuxvideo User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jeuxvideo.yaml`)

## Description
Jeuxvideo user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.jeuxvideo.com/profil/{{user}}?mode=infos
```

