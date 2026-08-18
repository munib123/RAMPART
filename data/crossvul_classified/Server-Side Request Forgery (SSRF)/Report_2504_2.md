# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2504_2
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2504_2`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 47-87 of the vulnerable file.

        internal AddOn(XmlTextReader xmlReader)
        {
            ReadXml(xmlReader);
        }

        internal AddOn(string planCode, string addOnCode, string name)
        {
            PlanCode = planCode;
            AddOnCode = addOnCode;
            Name = name;
        }

        #endregion

        /// <summary>
        /// Creates an addon
        /// </summary>
        public void Create()
        {
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
                UrlPrefix + Uri.EscapeUriString(PlanCode) + UrlPostfix,
                WriteXml,
                ReadXml);
        }

        /// <summary>
        /// Update an existing add on in Recurly
        /// </summary>
        public void Update()
        {
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Put,
                UrlPrefix + Uri.EscapeUriString(PlanCode) + UrlPostfix + Uri.EscapeUriString(AddOnCode),
                WriteXml,
                ReadXml);
        }

        /// <summary>
        /// Deletes this add on, making it inactive
        /// </summary>
        public void Delete()
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,7 +64,7 @@
         public void Create()
         {
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
-                UrlPrefix + Uri.EscapeUriString(PlanCode) + UrlPostfix,
+                UrlPrefix + Uri.EscapeDataString(PlanCode) + UrlPostfix,
                 WriteXml,
                 ReadXml);
         }
@@ -75,7 +75,7 @@
         public void Update()
         {
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Put,
-                UrlPrefix + Uri.EscapeUriString(PlanCode) + UrlPostfix + Uri.EscapeUriString(AddOnCode),
+                UrlPrefix + Uri.EscapeDataString(PlanCode) + UrlPostfix + Uri.EscapeDataString(AddOnCode),
                 WriteXml,
                 ReadXml);
         }
@@ -86,7 +86,7 @@
         public void Delete()
         {
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Delete,
-                UrlPrefix + Uri.EscapeUriString(PlanCode) + UrlPostfix + Uri.EscapeUriString(AddOnCode));
+                UrlPrefix + Uri.EscapeDataString(PlanCode) + UrlPostfix + Uri.EscapeDataString(AddOnCode));
         }
 
 
```
