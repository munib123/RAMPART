# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2504_6
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2504_6`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 29-69 of the vulnerable file.

        {
            ReadXml(reader);
        }

        internal CouponRedemption()
        {

        }


        /// <summary>
        /// Redeem an active coupon for an account
        /// </summary>
        /// <param name="accountCode"></param>
        /// <param name="currency"></param>
        internal static CouponRedemption Redeem(string accountCode, string couponCode, string currency, string subscriptionUuid=null)
        {
            var cr = new CouponRedemption {AccountCode = accountCode, Currency = currency, SubscriptionUuid = subscriptionUuid};

            var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
               "/coupons/" + Uri.EscapeUriString(couponCode) + "/redeem",
               cr.WriteXml,
               cr.ReadXml);

            return cr;

        }

        /// <summary>
        /// Removes a coupon from an account
        /// </summary>
        public void Delete()
        {
            var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Delete,
                "/accounts/" + Uri.EscapeUriString(AccountCode) +
                "/redemptions/" + Uri.EscapeUriString(Uuid));
            AccountCode = null;
            CouponCode = null;
            Currency = null;
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,7 +46,7 @@
             var cr = new CouponRedemption {AccountCode = accountCode, Currency = currency, SubscriptionUuid = subscriptionUuid};
 
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
-               "/coupons/" + Uri.EscapeUriString(couponCode) + "/redeem",
+               "/coupons/" + Uri.EscapeDataString(couponCode) + "/redeem",
                cr.WriteXml,
                cr.ReadXml);
 
@@ -60,8 +60,8 @@
         public void Delete()
         {
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Delete,
-                "/accounts/" + Uri.EscapeUriString(AccountCode) +
-                "/redemptions/" + Uri.EscapeUriString(Uuid));
+                "/accounts/" + Uri.EscapeDataString(AccountCode) +
+                "/redemptions/" + Uri.EscapeDataString(Uuid));
             AccountCode = null;
             CouponCode = null;
             Currency = null;
```
