# Vulnerability: Feiyuxing Information - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`feiyuxing-info-leak.yaml`)

## Description
Feiyuxing enterprise-level intelligent online behavior management system has authority bypass and information leakage vulnerabilities, which can obtain administrator rights and user passwords

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/request_para.cgi?parameter=wifi_get_5g_host
```

