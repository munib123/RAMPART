# HackerOne Report: Missing SPF header on revert.io
**Report ID:** 36459
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hi,

I noticed that there is no TXT record containing a SPF header:

#PoC
```
> dig TXT revert.io +short
"google-site-verification=ix6OUwvbN9AJLTcdg3ulWcMibIWGgUy_zWEXrWeRYE4"
```

The [SPF Header](http://de.wikipedia.org/wiki/Sender_Policy_Framework) can be used to prevent phishers from impersonating you/your company in the emails' FROM header. 

#Fix
You can fix that by generating an SPF-TXT record with all your outgoing mailservers.

All the best,
Sebastian

## Discussion & Remediation Timeline
