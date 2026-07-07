# HackerOne Report: CRITICAL full source code/config disclosure for Cameo
**Report ID:** 43998
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi!

The server at https://ci.cameo.tv/ has directory listing on and seems to host quiet a few debian packages containing extremely sensitive information (database paswords, API keys, you name it). One example is the config package containing 16 config files, even personal ones containing local passwords etc.

I think it's pretty obvious but you need to **IMMEDIATELY** remove the possibility to access this server from the internet. I also think that you should check your logs for this server, and consider changing all the passwords possibly leaked.

Mathias

## Discussion & Remediation Timeline
