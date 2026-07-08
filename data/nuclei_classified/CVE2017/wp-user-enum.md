# Vulnerability: WordPress REST API User Enumeration
**Classification:** CVE2017
**Source:** Nuclei Template (`wp-user-enum.yaml`)

## Description
The REST API exposed user data for all users who had authored a post of a public post type. WordPress 4.7.1 limits this to only post types which have specified that they should be shown within the REST API.

## Secure Mitigation
Install a WordPress plugin such as Stop User Enumeration. Stop User Enumeration is a security plugin designed to detect and prevent hackers scanning your site for user names.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-json/wp/v2/users/
GET {{BaseURL}}/?rest_route=/wp/v2/users/
```

