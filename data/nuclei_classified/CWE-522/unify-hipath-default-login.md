# Vulnerability: Unify HiPath Cordless IP - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`unify-hipath-default-login.yaml`)

## Description
Default login credentials on the Unify HiPath Cordless IP admin center were discovered.

## Secure Mitigation
Change the default password to a strong password.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
POST /cgi-bin/ikon_button.exe?page=1500&button=51&line=0&eventid=0&WbmSessionId=nosession&Username={{user}}&Password={{pass}}&CountryCode=en&NoSessionTimeout=false&SwitchLanguage=false HTTP/1.1
Host: {{Hostname}}
```

