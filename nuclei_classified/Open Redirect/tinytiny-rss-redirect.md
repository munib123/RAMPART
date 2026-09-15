# Nuclei Template: TinyTiny RSS Open Redirect
**Template ID:** tinytiny-rss-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Low
**Source:** Nuclei Template (`tinytiny-rss-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Detected an open redirect vulnerability in Tiny Tiny RSS where the return parameter in public.php was abused to redirect users to an attacker-controlled external URL after the authentication flow.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/public.php?return=http%3a%2f%2finteract.sh%2f&op=login&login=password=&profile=0
```

## References
- https://seclists.org/oss-sec/2019/q1/155
