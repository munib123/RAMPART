# Vulnerability: HPE System Management Anonymous Access
**Classification:** HP
**Source:** Nuclei Template (`hpe-system-management-anonymous.yaml`)

## Description
HPE system management anonymous access is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/chpstrt.php?chppath=Home
```

