# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2504_5
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2504_5`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 158-198 of the vulnerable file.

        }

        #endregion

        internal const string UrlPrefix = "/coupons/";

        /// <summary>
        /// Creates this coupon.
        /// </summary>
        public void Create()
        {
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
                UrlPrefix,
                WriteXml,
                ReadXml);
        }

        public void Update()
        {
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Put,
                UrlPrefix + Uri.EscapeUriString(CouponCode),
                WriteXmlUpdate);
        }

        public void Restore()
        {
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Put,
                UrlPrefix + Uri.EscapeUriString(CouponCode) + "/restore",
                WriteXmlUpdate);
        }

        /// <summary>
        /// Deactivates this coupon.
        /// </summary>
        public void Deactivate()
        {
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Delete,
                UrlPrefix + Uri.EscapeUriString(CouponCode));
        }

        public RecurlyList<Coupon> GetUniqueCouponCodes()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -175,14 +175,14 @@
         public void Update()
         {
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Put,
-                UrlPrefix + Uri.EscapeUriString(CouponCode),
+                UrlPrefix + Uri.EscapeDataString(CouponCode),
                 WriteXmlUpdate);
         }
 
         public void Restore()
         {
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Put,
-                UrlPrefix + Uri.EscapeUriString(CouponCode) + "/restore",
+                UrlPrefix + Uri.EscapeDataString(CouponCode) + "/restore",
                 WriteXmlUpdate);
         }
 
@@ -192,7 +192,7 @@
         public void Deactivate()
         {
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Delete,
-                UrlPrefix + Uri.EscapeUriString(CouponCode));
+                UrlPrefix + Uri.EscapeDataString(CouponCode));
         }
 
         public RecurlyList<Coupon> GetUniqueCouponCodes()
@@ -535,7 +535,7 @@
             var coupon = new Coupon();
 
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
-                Coupon.UrlPrefix + Uri.EscapeUriString(couponCode),
+                Coupon.UrlPrefix + Uri.EscapeDataString(couponCode),
                 coupon.ReadXml);
 
             return statusCode == HttpStatusCode.NotFound ? null : coupon;
```
