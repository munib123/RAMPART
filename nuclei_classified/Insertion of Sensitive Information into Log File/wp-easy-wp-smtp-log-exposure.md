# Nuclei Template: WordPress Easy WP SMTP - Log Exposure
**Template ID:** wp-easy-wp-smtp-log-exposure
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**Severity:** Medium
**CWE:** CWE-532
**Source:** Nuclei Template (`wp-easy-wp-smtp-log-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected WordPress Easy WP SMTP plugin debug log file exposed via directory listing, potentially revealing sensitive email contents including password reset links.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/easy-wp-smtp/logs/
```

## References
- https://blog.nintechnet.com/wordpress-easy-wp-smtp-plugin-fixed-zero-day-vulnerability/
- https://nvd.nist.gov/vuln/detail/CVE-2020-35234
- https://wpscan.com/vulnerability/10494
