# HackerOne Report: Stored XSS in api key of operator wallet
**Report ID:** 41758
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
1. Make an operation wallet
2. Open wallet settings
3. Press "New key"
4. In source code remove "maxlength=30" of key's name input tag - no length check on server-side
5. Fill name input with "<a href="example.com">asdf</a>" (PoC)
6. Press "Generate Key" 
7. After that when open wallet settings we got XSS.
8. In case we can share this type of wallet this xss can be used against another user.
Problem is that there is some filter on server side and at this moment i trying to find way to bypass it and fire javascript command.

## Discussion & Remediation Timeline
