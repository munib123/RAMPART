# HackerOne Report: XSS with Time-of-Day Format
**Report ID:** 52822
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
- Go to your user preferences
- Put the following into Time-of-Day Format (with the quote): 
 `'<\i\m\g \s\r\c=x \o\n\e\r\r\o\r=\a\l\e\r\t(\'X\S\S\')\>' `
- Open a repository (diffusion) -> XSS-Popup

The repository file-overview is the only place where I could see the XSS so far.

Because it's a user own preference, it is not easy to actually do something malicious in a real-world scenario. But it's definitely possible if you think hard enough about it :)

Cheers,
David

mongoose

## Discussion & Remediation Timeline
