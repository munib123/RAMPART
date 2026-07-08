# Vulnerability: Foursquare User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`foursquare.yaml`)

## Description
Foursquare user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://foursquare.com/{{user}}
```

