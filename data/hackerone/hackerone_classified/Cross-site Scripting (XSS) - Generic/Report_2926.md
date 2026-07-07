# HackerOne Report: Stored XSS 
**Report ID:** 2926
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,

Go to this URL https://sehacure.slack.com/account/preferences?updated_highlight_words=1
and in the highlight words option please fill the XSS vector as 

</textarea><script>prompt(document.cookie);</script>

Your cookie will be reflected.

Best regards,
Anand

## Discussion & Remediation Timeline
