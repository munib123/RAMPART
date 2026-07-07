# HackerOne Report: owncloud.com: Content Sniffing not disabled
**Report ID:** 83251
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
URL :- https://owncloud.com

Issue description :-
There was no "X-Content-Type-Options" HTTP header with the value nosniff set in the response. The lack of this header causes that certain browsers, try to determine the content type and encoding of the response even when these properties are defined correctly. This can make the web application vulnerable against Cross-Site Scripting (XSS) attacks. E.g. the Internet Explorer and Safari treat responses with the content type text/plain as HTML, if they contain HTML tags.

Issue remediation :-
Set the following HTTP header at least in all responses which contain user input:
X-Content-Type-Options: nosniff

## Discussion & Remediation Timeline
