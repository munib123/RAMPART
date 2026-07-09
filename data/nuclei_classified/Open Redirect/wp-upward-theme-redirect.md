# Nuclei Template: WordPress Upward Themes <1.5 - Open Redirect
**Template ID:** wp-upward-theme-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**Source:** Nuclei Template (`wp-upward-theme-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Upward Themes 1.5 accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks. An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL. By modifying the URL value to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/Upward/go.php?https://interact.sh
```

## References
- https://cxsecurity.com/issue/WLB-2020030133
