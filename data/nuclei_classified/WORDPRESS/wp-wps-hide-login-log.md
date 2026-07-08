# Vulnerability: WordPress WPS Hide Login - Error Log Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-wps-hide-login-log.yaml`)

## Description
Detected whether the WPS Hide Login plugin’s /classes/ directory was exposed with directory listing enabled due to server misconfiguration, potentially disclosing PHP error logs or source code.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wps-hide-login/classes/error_log
```

