# HackerOne Report: broken authentication
**Report ID:** 23921
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hello,

Steps to Replicate:-

1) Create a concrete5 account.
2) request a Password Reset link in Email( don't use it)
3) Login with the Desired Password
4) Change the Password Several Times From Settings ( This destroys all the Active Sessions) in my case i've made upto 10 Password changes.
5) After several password changes, you can use that Password reset link( mentioned in Step 2) to change your Password.

I would Suggest Expiring all the Password Reset tokens After Several Successful Password Changes has been made to the Account. Supposing That these Changes are made by the User of the account itself, Because an Active Password token After Several Session Destructions Should not be Active anymore.

Thanks!

## Discussion & Remediation Timeline
