# HackerOne Report: Bypass auth.email-domains (2)
**Report ID:** 2233
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
This vulnerability has the same effect as my previously reported bug [#2224 Bypass `auth.email`-domains](https://hackerone.com/reports/2224), but uses a very different approach, bypassing the current fix.

Instead of truncating through length, this vulnerability uses truncation via MySQL’s (weird) behaviour on inserting Unicode characters with code points greater than `0xFFFF` into columns that have a `utf8` charset. MySQL then truncates a string as soon as it reaches such a character. For more info, see [How to support full Unicode in MySQL databases](http://mathiasbynens.be/notes/mysql-utf8mb4) by @mathias.

To replicate, register an account with following address: `attacker@gmail.com𝌆@allowed-domain.com`.

I would suggest to reconsider not verifying email addresses as was mentioned [here](https://secure.phabricator.com/D8308#5).

## Discussion & Remediation Timeline
