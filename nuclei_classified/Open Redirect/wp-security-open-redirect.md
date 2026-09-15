# Nuclei Template: WordPress All-in-One Security <=4.4.1 - Open Redirect
**Template ID:** wp-security-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`wp-security-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress All-in-One Security plugin through 4.4.1 contains an open redirect vulnerability which can expose the actual URL of the hidden login page feature. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?aiowpsec_do_log_out=1&after_logout=https://interact.sh
```

## Remediation
Upgrade to 4.4.2 or later.

## References
- https://wpscan.com/vulnerability/9898
- https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-all-in-one-wp-security-firewall-open-redirect-4-4-1
