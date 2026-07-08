# Vulnerability: Gitlab SAML - Detection
**Classification:** PANEL
**Source:** Nuclei Template (`gitlab-saml.yaml`)

## Description
The presence of SAML-based authentication on GitLab instances. SAML is commonly used for Single Sign-On (SSO) integrations, which allows users to authenticate with GitLab using an external Identity Provider (IdP).

## Vulnerable Code Pattern / Exploit Payload
```http
GET /users/auth/saml/metadata HTTP/1.1
Host: {{Hostname}}
```

