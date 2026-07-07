# HackerOne Report: Improperly implemented password recovery link functionality
**Report ID:** 809
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
I took a look at live install of Phabricator (https://secure.phabricator.com/) and noticed, that the user gets automatically logged in after clicking the password recovery link (this link is sent to the user's mail). This authentication takes place before the user is asked to enter a new password twice. This can be used be the attacker to log in a user to the attacker's account - the attacker generates a password recovery link to his account, sends it to the user and the user becomes logged in to the attacker's account, when he clicks the link delivered by the attacker.

## Discussion & Remediation Timeline
