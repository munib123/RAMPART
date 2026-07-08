# Vulnerability: NoVus IP Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`novus-ip-camera.yaml`)

## Description
NoVus IP login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Pages/login.htm
```

