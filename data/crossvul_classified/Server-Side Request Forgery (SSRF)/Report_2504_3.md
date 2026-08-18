# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2504_3
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2504_3`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 98-138 of the vulnerable file.

            if(UnitAmountInCents > UnitAmountMax)
                throw new PropertyOutOfRangeException("UnitAmountInCents",
                    string.Format("Adjustment's UnitAmountInCents may be at most {0}.", UnitAmountMax));
        }

        internal Adjustment(XmlTextReader xmlReader)
        {
            ReadXml(xmlReader);
        }

        #endregion


        /// <summary>
        /// Create a new adjustment in Recurly
        /// </summary>
        public void Create()
        {
            // POST /accounts/<account code>/adjustments
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
                UrlPrefix + Uri.EscapeUriString(AccountCode) + UrlPostfix,
                WriteXml,
                ReadXml);
        }

        /// <summary>
        /// Deletes an adjustment from an account.
        /// 
        /// Adjustments can only be deleted when not invoiced
        /// </summary>
        public void Delete()
        {
            // DELETE /adjustments/<uuid>
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Delete,
                UrlPostfix + Uri.EscapeUriString(Uuid));
        }


        #region Read and Write XML documents

        internal override void ReadXml(XmlTextReader reader)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,7 +115,7 @@
         {
             // POST /accounts/<account code>/adjustments
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
-                UrlPrefix + Uri.EscapeUriString(AccountCode) + UrlPostfix,
+                UrlPrefix + Uri.EscapeDataString(AccountCode) + UrlPostfix,
                 WriteXml,
                 ReadXml);
         }
@@ -129,7 +129,7 @@
         {
             // DELETE /adjustments/<uuid>
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Delete,
-                UrlPostfix + Uri.EscapeUriString(Uuid));
+                UrlPostfix + Uri.EscapeDataString(Uuid));
         }
 
 
@@ -284,7 +284,7 @@
         {
             var adjustment = new Adjustment();
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
-                "/adjustments/" + Uri.EscapeUriString(uuid),
+                "/adjustments/" + Uri.EscapeDataString(uuid),
                 adjustment.ReadXml);
             return adjustment;
         }
```
