# HackerOne Report: Back - Refresh - Attack To  Obtain User Credentials
**Report ID:** 21064
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Back - refresh attack is attack which enables an adversary to obtain application credentials by going by to previous page and re-submitting the expired-document.

How to perform:
1. Register to https://<some-site>/auth/register/
2. Once registered, press "Back" on the browser window. Now you'll see the "Document Expired" page.
3. Now run an interceptor (burp/tamper data)
4. Click "Tray again" on the web page
5. Click "Re-send data"
6. Watch the intercepted request.

You'll observe that login credentials both email and passwords being resubmitted by browser get captured.

## Discussion & Remediation Timeline
