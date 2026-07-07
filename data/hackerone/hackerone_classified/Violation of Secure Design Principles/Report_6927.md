# HackerOne Report: Session cookie can be leaked over an unencrypted HTTP connection
**Report ID:** 6927
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Because the session cookie, `session`, does not have the [Secure flag](https://www.owasp.org/index.php/SecureFlag) set, it is possible that the session cookie leaks over an unencrypted connection. An attacker could exploit this issue by (for example) tricking a user into clicking on a link to a page with the following HTML code:

    <img src="http://www.irccloud.com">

When the user visits the page, the browser will send a request to www.irccloud.com, over an unencrypted connection (note the **http** instead of **https**), containing the session cookie. When this happens, an attacker can easily take over the user's session with a *Man-In-The-Middle attack*.

I recommend setting the Secure flag, so browsers who support the Secure flag will prevent the transmission of a cookie in an unencrypted HTTP packet.

## Discussion & Remediation Timeline
