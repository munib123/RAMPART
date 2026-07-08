# Vulnerability: Trend Micro Apex One Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`trendmicro-apexone-panel.yaml`)

## Description
Trend Micro Apex One login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/officescan/console/html/cgi/cgiChkMasterPwd.exe
GET {{BaseURL}}/SMB/console/html/cgi/cgiChkMasterPwd.exe
```

