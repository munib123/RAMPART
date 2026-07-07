# HackerOne Report: Server responds with the server error logs on account creation
**Report ID:** 57692
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
**Impact**
Poorly protected response can provide a gold mine of information to an attacker, disclosing a host of sensitive information such as function and file names. This information may enable the attacker
to immediately or later compromise the entire application.

**PoC**

1. Create a new wallet.

2. Intercept the request using a proxy tool.

3. Edit the `bankAccountType` to anything other than CHECKING

The server responds with error log of the server in the header of the response, see attached picture.

Thanks
crab

## Discussion & Remediation Timeline
