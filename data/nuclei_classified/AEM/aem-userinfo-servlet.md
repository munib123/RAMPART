# Vulnerability: AEM UserInfo Servlet Credentials Exposure
**Classification:** AEM
**Source:** Nuclei Template (`aem-userinfo-servlet.yaml`)

## Description
Adobe Experience Manager UserInfoServlet is exposed which allows an attacker to bruteforce credentials. You can get valid usernames from jcr:createdBy, jcr:lastModifiedBy, cq:LastModifiedBy attributes of any JCR node.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/libs/cq/security/userinfo.json
```

