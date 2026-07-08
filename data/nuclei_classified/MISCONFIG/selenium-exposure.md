# Vulnerability: Selenium - Node Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`selenium-exposure.yaml`)

## Description
Selenium was shown to have an exposed node. If a Selenium node is exposed without any form of authentication, remote command execution could be possible if chromium is configured. By default the port is 4444, still, most of the internet facing are done through reverse proxies.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wd/hub
```

