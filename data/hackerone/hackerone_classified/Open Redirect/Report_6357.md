# HackerOne Report: https://www.khanacademy.org/login open-redirect
**Report ID:** 6357
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Hi,

I found a bypass in the redirects :
`https://www.khanacademy.org/login?continue=http://www.olivierbeg.nl` won't work.
`https://www.khanacademy.org/login?continue=http:/www.olivierbeg.nl` will work :-)

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
