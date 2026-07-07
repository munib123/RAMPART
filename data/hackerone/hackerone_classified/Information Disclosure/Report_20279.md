# HackerOne Report: Verbose SQL error messages
**Report ID:** 20279
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
When an SQL error occurs, a verbose error is displayed showing the full query and the path of the include file on the server. This is valuable information, revealing the structure of the database and the layout of files on the server.

## Discussion & Remediation Timeline
