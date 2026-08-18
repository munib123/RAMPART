# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2504_8
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2504_8`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 307-347 of the vulnerable file.

            return Id.GetHashCode();
        }

        #endregion
    }

    public sealed class GiftCards
    {
        internal const string UrlPrefix = "/gift_cards/";

        /// <summary>
        /// Lookup a Recurly gift card
        /// </summary>
        /// <param name="id">The long id of the gift card</param>
        /// <returns></returns>
        public static GiftCard Get(long id)
        {
            var giftCard = new GiftCard();
            // GET /gift_cards/<id>
            var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
                UrlPrefix + Uri.EscapeUriString(id.ToString()),
                giftCard.ReadXml);

            return statusCode == HttpStatusCode.NotFound ? null : giftCard;
        }

        /// <summary>
        /// Lists gift cards
        /// </summary>
        /// <param name="gifterAccountCode">A gifter's account code to filter by (may be null)</param>
        /// <param name="recipientAccountCode">A recipients's account code to filter by (may be null)</param>
        /// <param name="filter">FilterCriteria used to apply server side sorting and filtering</param>
        /// <returns></returns>
        public static RecurlyList<GiftCard> List(string gifterAccountCode = null, string recipientAccountCode = null, FilterCriteria filter = null)
        {
            filter = filter ?? FilterCriteria.Instance;
            var parameters = filter.ToNamedValueCollection();

            if (gifterAccountCode != null)
                parameters["gifter_account_code"] = gifterAccountCode;
            if (recipientAccountCode != null)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -324,7 +324,7 @@
             var giftCard = new GiftCard();
             // GET /gift_cards/<id>
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
-                UrlPrefix + Uri.EscapeUriString(id.ToString()),
+                UrlPrefix + Uri.EscapeDataString(id.ToString()),
                 giftCard.ReadXml);
 
             return statusCode == HttpStatusCode.NotFound ? null : giftCard;
```
