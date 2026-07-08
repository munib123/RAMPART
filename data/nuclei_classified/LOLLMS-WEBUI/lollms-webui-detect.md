# Vulnerability: LoLLMS WebUI - Detect
**Classification:** LOLLMS-WEBUI
**Source:** Nuclei Template (`lollms-webui-detect.yaml`)

## Description
An instance running LoLLMS WebUI was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

