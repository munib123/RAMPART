# HackerOne Report: Unvalidated Channel names causes IRC Command Injection
**Report ID:** 29480
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
IRCCloud does not validate the channel names created by a user causing it to be parsed as an IRC command such as QUIT.

This means the user can have their clients force-closed by a malicious channel name.

This could also lead to other command injections such as forcing the handover of channels to other users for example (not tested).

Here is my PoC of a malicious channel name:
``#treehouse'){%0a%0dQUIT``

``15:03:49  ⇐ SySTeM quit (sid12267@reid-aqa3e3.irccloud.com) Client exited
15:04:02  → SySTeM joined #treehouse'){%0a%0dQUIT (sid12267@reid-aqa3e3.irccloud.com)
15:04:04  ⇐ SySTeM quit (sid12267@reid-aqa3e3.irccloud.com) Client exited``

If you require any further information, please let me know.

All the best,
Richard Clifford

## Discussion & Remediation Timeline
