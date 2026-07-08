# Vulnerability: StreamElements User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`streamelements.yaml`)

## Description
StreamElements user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.streamelements.com/kappa/v2/channels/{{user}}
```

