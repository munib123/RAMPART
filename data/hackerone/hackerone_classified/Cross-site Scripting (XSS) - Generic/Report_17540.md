# HackerOne Report: Reflected XSS in Pastebin-view
**Report ID:** 17540
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
The paste ID passed in via the URL in the Pastebin-view is inserted between `<script>` tags unsanitised. This leads to reflected XSS that bypasses all major XSS protection software (Chrome, IE...).

Normal request: https://www.irccloud.com/pastebin/nhm4f6pB
Proof-of-concept: https://www.irccloud.com/pastebin/";alert(0);%2F%2F

I've never used **HackerOne** before so please let me know if my report is missing something important!

## Discussion & Remediation Timeline
