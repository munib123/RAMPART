# Vulnerability: Comtrend ADSL - Remote Code Execution
**Classification:** ROUTER
**Source:** Nuclei Template (`comtrend-password-exposure.yaml`)

## Description
Comtrend ADSL CT-5367 C01_R12 router is susceptible to remote code execution. A remote user can execute arbitrary commands via the telnet interface, The password for this interface is leaked to unauthenticated users via the password.cgi endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/password.cgi
```

