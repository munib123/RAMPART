# Vulnerability: WordPress Grimag <1.1.1 - Open Redirection
**Classification:** CWE-601
**Source:** Nuclei Template (`wp-grimag-open-redirect.yaml`)

## Description
WordPress Grimag theme before 1.1.1 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Secure Mitigation
Fixed in 1.1.1.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/Grimag/go.php?https://interact.sh
```

