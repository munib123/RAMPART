# HackerOne Report: Vulnerable to JavaScript injection. (WXS)  (Javascript injection)!
**Report ID:** 54631
**Vulnerability Class:** Command Injection - Generic

## Vulnerability Information & PoC
Vulnerable to JavaScript injection. (WXS)

Description:
Java script injected in activity: 
net.hockeyapp.android.UpdateActivity with injection String: document.getElementsByTagName('body')[0].setAttribute('style', 'background-color: red');

Recommended Solution:
Local HTML modifications via malware or other apps results in execution of malicious JavaScript in the presentation layer of the app. This may result in information theft.

Verify that JavaScript and Plugin support is disabled for any WebViews (usually the default).

Ensure that all UIWebView calls do not execute without proper input validation. Apply filters for dangerous JavaScript characters if possible, using a whitelist over blacklist character policy before rendering.

References:
Mobile Top 10 2014-M7(Client Side Injection) - OWASP
Adventures with Android WebViews (Javascript injection) - OWASP


Thanks,


## Discussion & Remediation Timeline
