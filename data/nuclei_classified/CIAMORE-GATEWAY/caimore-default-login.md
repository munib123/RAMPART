# Vulnerability: CAIMORE Gateway  Default Login - Detect
**Classification:** CIAMORE-GATEWAY
**Source:** Nuclei Template (`caimore-default-login.yaml`)

## Description
The gateway of Xiamen Caimao Communication Technology Co., Ltd. is designed with open software architecture. It is a metal shell design, with two Ethernet RJ45 interfaces, and an industrial design wireless gateway using 3G/4G/5G wide area network for Internet communication. There is a command execution vulnerability in the formping file of the gateway of Xiamen Caimao Communication Technology Co., Ltd. An attacker can use this vulnerability to arbitrarily execute code on the server side, write to the back door, obtain server permissions, and then control the entire web server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /index.asp HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Authorization: Basic {{base64(username + ':' + password)}}
```

