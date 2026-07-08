# Vulnerability: phpSysInfo Exposure
**Classification:** CONFIG
**Source:** Nuclei Template (`phpsys-info.yaml`)

## Description
phpSysInfo: a customizable PHP script that displays information about your system nicely

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phpsysinfo/index.php?disp=bootstrap
```

