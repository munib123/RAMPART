# HackerOne Report: PHP and Wordpress version disclosure
**Report ID:** 9516
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
**Vulnerable File**
google-authenticator-per-user-prompt/views/requirements-error.php

**Description**
That file discloses the PHP version and Wordpress version to the world.Which is not a bug actually,but these information can be helpful to demonstrate further devastating bugs.

**Suggestion**
I saw that you rejected many path disclosure reports cause those are not in your hand.It depends upon server settings,how that will handle error messages.But this case is different.Its not actually an error message.And cant be mitigated by switching off error display.
I suggest you to keep such actions so that unauthorized users could not use this file directly.

## Discussion & Remediation Timeline
