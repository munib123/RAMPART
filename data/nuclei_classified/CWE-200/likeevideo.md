# Vulnerability: Likeevideo User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`likeevideo.yaml`)

## Description
Likeevideo user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://likee.video/@{{user}}
```

