# Vulnerability: Virtual EMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`virtual-ema-detect.yaml`)

## Description
Virtual EMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/virtualems/Login.aspx
GET {{BaseURL}}/VirtualEms/Login.aspx
```

