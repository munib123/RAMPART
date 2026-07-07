# HackerOne Report: IFRAME loaded from External Domains  
**Report ID:** 5205
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Hello coinbase,

Iam saikiran.Iam a security researcher.while i was going through your site i found that your website loads an iframe from an external website which might not be trustworthy.IFRAME has been loaded in the page 'https://coinbase.com/charts' from 'www.statsmix.com' which is an external domain that might not be trustworthy.

As this is a bit-coin wallet website it is not advisable to load iframes or any type of data from other websites...it would be very dangerous if the external domain misuses this..if he changes that i frame into any exploitation method he can get into your website easily.

SOLUTION.

just stop using external domain data in your webserver..what ever you use,use your own data or just try to keep that data on your server only..

## Discussion & Remediation Timeline
