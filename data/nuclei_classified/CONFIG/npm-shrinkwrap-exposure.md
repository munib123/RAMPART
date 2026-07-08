# Vulnerability: Node Shrinkwrap Exposure
**Classification:** CONFIG
**Source:** Nuclei Template (`npm-shrinkwrap-exposure.yaml`)

## Description
A file created by npm shrinkwrap. It is identical to package-lock.json.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/npm-shrinkwrap.json
```

