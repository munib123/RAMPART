# HackerOne Report: Potential for financial loss, negative Values for "Buy fee" and "Sell Fee"
**Report ID:** 74147
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
**Issue**
It is possible to set negative values for the Buy Fee and Sell Fee, which will cause unexpected transfers etc. 
as these settings override the settings at the location.

**PoC**
1. Go to the Operator Wallet's Settings.
2. Click on the users tab.
3. Select any user. 
4. Go to settings tab of that user.
5. Select any kiosk.
6. Click on Save .Capture the request and set negative values for Sell Fee and Buy Fee.

To verify, next time when you try to view these settings, the server responds with the set negative values.

Thanks
crab

## Discussion & Remediation Timeline
