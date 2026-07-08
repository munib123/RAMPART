# Vulnerability: Nacos 1.x - Authentication Bypass
**Classification:** NACOS
**Source:** Nuclei Template (`nacos-auth-bypass.yaml`)

## Description
Nacos 1.x was discovered. A default Nacos instance needs to modify the application.properties configuration file or add the JVM startup variable Dnacos.core.auth.enabled=true to enable the authentication function (reference: https://nacos.io/en-us/docs/auth.html). But authentication can still be bypassed under certain circumstances and any interface can be called as in the following example that can add a new user (POST https://127.0.0.1:8848/nacos/v1/auth/users?username=test&password=test). That user can then log in to the console to access, modify, and add data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nacos/v1/auth/users?pageNo=1&pageSize=9
GET {{BaseURL}}/v1/auth/users?pageNo=1&pageSize=9
```

