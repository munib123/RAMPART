# Vulnerability: Flickr User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`flickr.yaml`)

## Description
Flickr user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.flickr.com/photos/{{user}}/
```

