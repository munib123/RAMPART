# Vulnerability: DeviantArt User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`deviantart.yaml`)

## Description
DeviantArt user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.deviantart.com/{{user}}
```

