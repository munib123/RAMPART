# Vulnerability: Artists & Clients User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`artists-clients.yaml`)

## Description
Artists & Clients user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://artistsnclients.com/people/{{user}}
```

