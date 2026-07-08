# Vulnerability: Gitblit - Default Login
**Classification:** GITBLIT
**Source:** Nuclei Template (`gitblit-default-login.yaml`)

## Description
Gitblit Default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /?wicket:interface=:0:userPanel:loginForm::IFormSubmitListener:: HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

wicket%3AbookmarkablePage=%3Acom.gitblit.wicket.pages.MyDashboardPage&id1_hf_0=&username={{username}}&password={{password}}
```

