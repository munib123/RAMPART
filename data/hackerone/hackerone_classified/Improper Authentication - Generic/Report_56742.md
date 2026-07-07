# HackerOne Report: SPF whitelist of mandrill leads to email forgery
**Report ID:** 56742
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
I just sent a forged email to support@hackerone.com that appears to originate from mike.brooks@hackerone.com.   I was able to do this because of the following  SPF record:

dig txt hackerone.com
hackerone.com.		299	IN	TXT	"v=spf1 include:_spf.google.com include:sendgrid.net include:mail.zendesk.com include:spf.mandrillapp.com ~all"

Using my own mandrill account I can send email which appears to originate from hackerone.  This is useful in phishing,  and this type of vulnerability is news worthy (http://bits.blogs.nytimes.com/2015/04/09/sendgrid-email-breach-was-used-to-attack-coinbase-a-bitcoin-exchange/).

The patch is pretty simple.  Complete your mandril registration process.  This will lock out other mandrill users from sending email that originates from *@hackerone.com.

Let me know if you need me to send another forged email,  or if  have any other questions.

Thanks,
Mike Brooks from Bishop Fox.


## Discussion & Remediation Timeline
