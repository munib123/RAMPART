# Vulnerability: nginxWebUI ≤ 3.5.0 runCmd - Remote Command Execution
**Classification:** NGINX
**Source:** Nuclei Template (`nginxwebui-runcmd-rce.yaml`)

## Description
nginxWebUI’s runCmd feature and is caused by incomplete validation of user input. Attackers can exploit the vulnerability by crafting malicious data to execute arbitrary commands on a vulnerable server without authorization.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/AdminPage/conf/runCmd?cmd=id
```

