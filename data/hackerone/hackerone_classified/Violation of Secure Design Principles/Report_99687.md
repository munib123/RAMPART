# HackerOne Report: profile cover can also load external URL's 
**Report ID:** 99687
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hi,

I have to option to change my cover background (https://hackerone.com/{program_name}/edit). 
When I insert `#360e0e url('http://www.google.com')` as background "color" it will make a connection to http://www.google.com (If IE is used).

I can't save it so it won't affect any other people but it doesn't look "by design".

Kind regards,

Olivier

## Discussion & Remediation Timeline
