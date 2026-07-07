# HackerOne Report: Vimeo.com - reflected xss vulnerability
**Report ID:** 42584
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi.

I want to report a Reflected xss vulnerability that I found in www.vimeo.com website and which can affect the safety of your users. This vulnerability allows an attacker to inject in web pages javascript content for sending malicious scripts to an unsuspecting user. This flaw can access any cookies, session tokens, or other sensitive information retained by victim's browser and used with that site.

PoC Link: http://vimeo.com/enhancer?section_type=xss%27%2bprompt(1)%2b%27
Type: GET XSS
Vulnerable Parameter: `section_type`
Steps for reproducing this flaw: Open the PoC Link in any web browser and you will see that the value of `section_tab` GET parameter is inserted in the html page without being filtered. As a result, the javascript function alert() used as a payload for this PoC will be called.

Regards,
Coltuneac Alexandru

## Discussion & Remediation Timeline
