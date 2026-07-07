# HackerOne Report: files.acrobat.com stored XSS via send file
**Report ID:** 50358
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Description of the sending file vulnerable to xss
Proof:
https://files.acrobat.com/a/preview/c9efeb22-75a5-4268-ad57-f8f694aa7a1d

steps to reproduce:
- go to https://cloud.acrobat.com/send and select file to send
-  check an option "Create Anonymous Link"
- input any subject 
- input payload `<img src=x onerror=alert(1)>` to description
- click "Create Link" button
- follow to created link

## Discussion & Remediation Timeline
