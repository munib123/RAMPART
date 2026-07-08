# Vulnerability: Adobe Experience Manager - Dispatcher Bypass
**Classification:** ADOBE
**Source:** Nuclei Template (`aem-dispatcher-bypass.yaml`)

## Description
Detected potential Adobe Experience Manager (AEM) Dispatcher misconfigurations that could have allowed bypassing request filtering, exposing internal endpoints, or permitting unauthorised access to restricted resources.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{paths}} HTTP/1.1
Host: {{Hostname}}
```

