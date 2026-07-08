# Vulnerability: FanCentro User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fancentro.yaml`)

## Description
FanCentro user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://fancentro.com/api/profile.get?profileAlias={{user}}&limit=1
```

