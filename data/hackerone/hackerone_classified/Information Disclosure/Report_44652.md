# HackerOne Report: Insecure crossdomain.xml
**Report ID:** 44652
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi,

https://mobilevikings.be/crossdomain.xml contains the following xml file:
```
<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*" secure="true" />
</cross-domain-policy>
```

This will make any one able to receive content from https://mobilevikings.be/.
More information about this issue is available here:
http://gursevkalra.blogspot.nl/2013/08/bypassing-same-origin-policy-with-flash.html
Best regards,

Olivier Beg

## Discussion & Remediation Timeline
