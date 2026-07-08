# Vulnerability: Joomla - User Registration Enabled
**Classification:** JOOMLA
**Source:** Nuclei Template (`joomla-registration-enabled.yaml`)

## Description
Detected Joomla user registration enabled, allowing anyone to create accounts on the site. If not intentionally configured, this could lead to unauthorized access or spam account creation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_users&view=registration
```

