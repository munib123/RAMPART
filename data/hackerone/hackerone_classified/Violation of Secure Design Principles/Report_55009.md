# HackerOne Report: Frameset Proxy Problem
**Report ID:** 55009
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
I was testing out the proxy pages (http://fct.li, http://staging.fct.li) and I found that if I create an HTML page with a frameset (not to be confused with iframe), then I would be able to get rid of the dialog (top right corner) that reads: "You're looking at this page through Factlink (visit original page)". So the page looks like its completely hosted by you guys.

Example (frameset):
http://fct.li/?url=http://zenzr.org/fl-frameset.html
http://staging.fct.li/?url=http://zenzr.org/fl-frameset.html

This is the source code for a frameset:
<frameset rows="100%,*" style="border:0; frameborder:0; framespacing:0;">
        <frame src="http://www.example.com/" style="border:0;" marginwidth="0" marginheight="0" noresize/>
</frameset>

A  hacker could easily create a phishing page and steal the user's credentials.

## Discussion & Remediation Timeline
