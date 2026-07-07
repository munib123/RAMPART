# HackerOne Report: "learn more here", reward email - domain expired.
**Report ID:** 52532
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Hi,

Today I received an e-mail about a reward, below the e-mail there is something about `drastically reduced fees from Coinbase`, to be exactly, the following:

```
Thanks to drastically reduced fees from Coinbase, you are eligible to receive a 5% bonus when you receive your bounty payout in Bitcoin. Curious if Bitcoin is appropriate in your country? Learn more [here](http://bitlegal.io/).
```

The domain where "learn more here" points to is expired. See: http://www.nic.io/cgi-bin/whois?query=bitlegal.io this could potentially lead to phishing attacks.

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
