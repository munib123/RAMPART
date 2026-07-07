# HackerOne Report: Open Redirection Security Filter bypassed
**Report ID:** 44157
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Hi,

The application is vulnerable to Open Redirection using a basic filter bypass which it was using for security against open redirection.

Here is the vulnerable link:
https://vimeo.com/tools/edit?image=http://securityidiots.com?vimeocdn.com/.png

Weakness in filter against Open Redirect.: Actually the application is using the below given filters against open redirection.
1. URL must contain "vimeocdn.com/"
2. It should end with an image extention for example jpg, png etc

The problem with the above filter can be seen in my payload, as i included both of the requirements and still redirected the user to my url.

Solution : Below changes can be made to the security.
If "https://f.vimeocdn.com/" is the URL for images then hardcode it and take the rest of input from GET so that in any case we will have "https://f.vimeocdn.com/" before the URL and user wont be able to do a open redirect to any other domain.

## Discussion & Remediation Timeline
