# Vulnerability: Polycom HDX - Web Interface Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`polycom-hdx-web-exposure.yaml`)

## Description
Detecetd Polycom HDX video conferencing system web interface, potentially allowing unauthorized access to device configuration and video calls.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

