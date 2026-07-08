# Vulnerability: Adobe Experience Manager (AEM) - Anonymous JCR Node Creation
**Classification:** AEM
**Source:** Nuclei Template (`aem-anonymous-write.yaml`)

## Description
Anonymous users can create new JCR nodes via the AEM POST Servlet, which may allow attackers to inject malicious content, achieve persistent XSS, or abuse servlets registered by resource types for further attacks.

## Secure Mitigation
Configure proper access control lists (ACLs) on AEM paths to prevent anonymous users from creating JCR nodes. Review and restrict permissions on the POST servlet to authenticated users only.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
POST {{path}}{{extension}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

<html>{{marker}}</html>
```

