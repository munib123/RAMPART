# Vulnerability: SpiderControl SCADA Web Server - Sensitive Information Exposure
**Classification:** SPIDERCONTROL
**Source:** Nuclei Template (`spidercontrol-scada-server-info.yaml`)

## Description
SpiderControl SCADA Web Server is vulnerable to sensitive information exposure. Numerous, market-leading OEM manufacturers - from a wide variety of industries - rely on SpiderControl.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/GetSrvInfo.exe
```

