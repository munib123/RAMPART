# Nuclei Template: WordPress Wordfence - WAF Logs and Data Disclosure
**Template ID:** wordfence-waf-logs-disclosure
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** Low
**CWE:** CWE-538
**Source:** Nuclei Template (`wordfence-waf-logs-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
The Wordfence Security plugin creates various log and data files in the wflogs directory. If directory listing is enabled or files are directly accessible, sensitive information about blocked attacks, IP addresses, and firewall configuration may be exposed.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-content/wflogs/
GET {{BaseURL}}/wp-content/plugins/wordfence/lib/wflogs/
GET {{BaseURL}}/wp-content/plugins/wordfence/tmp/
```

## References
- https://wordpress.org/support/topic/detect-suspicious-content-in-word-fence-wflogs-in-my-site/
- https://wordpress.org/support/topic/syn_sent-in-wflogs-filename-php/
