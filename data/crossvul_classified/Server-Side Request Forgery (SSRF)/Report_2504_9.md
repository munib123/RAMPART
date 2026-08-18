# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2504_9
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2504_9`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 104-144 of the vulnerable file.

        {
            return OriginalInvoiceNumberPrefix + Convert.ToString(OriginalInvoiceNumber);
        }

        /// <summary>
        /// Returns a PDF representation of an invoice
        /// </summary>
        /// <param name="acceptLanguage">Language for invoice, defaults to en-US.</param>
        /// <returns></returns>
        public byte[] GetPdf(string acceptLanguage = "en-US")
        {
            return Client.Instance.PerformDownloadRequest(memberUrl(), "application/pdf", acceptLanguage);
        }

        /// <summary>
        /// Post an invoice on an account using it's pending charges
        /// </summary>
        public void Create(string accountCode)
        {
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
                "/accounts/" + Uri.EscapeUriString(accountCode) + Invoice.UrlPrefix,
                WriteXml,
                ReadXml);
        }

        /// <summary>
        /// Preview an invoice on an account using it's pending charges
        /// </summary>
        public void Preview(string accountCode)
        {
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
                "/accounts/" + Uri.EscapeUriString(accountCode) + Invoice.UrlPrefix + "preview",
                WriteXml,
                ReadXml);
        }

        /// <summary>
        /// Marks an invoice as paid successfully
        /// </summary>
        public void MarkSuccessful()
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,7 +121,7 @@
         public void Create(string accountCode)
         {
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
-                "/accounts/" + Uri.EscapeUriString(accountCode) + Invoice.UrlPrefix,
+                "/accounts/" + Uri.EscapeDataString(accountCode) + Invoice.UrlPrefix,
                 WriteXml,
                 ReadXml);
         }
@@ -132,7 +132,7 @@
         public void Preview(string accountCode)
         {
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
-                "/accounts/" + Uri.EscapeUriString(accountCode) + Invoice.UrlPrefix + "preview",
+                "/accounts/" + Uri.EscapeDataString(accountCode) + Invoice.UrlPrefix + "preview",
                 WriteXml,
                 ReadXml);
         }
@@ -453,7 +453,7 @@
     {
         public static RecurlyList<Invoice> List(string accountCode)
         {
-            return new InvoiceList("/accounts/" + Uri.EscapeUriString(accountCode) + "/invoices");
+            return new InvoiceList("/accounts/" + Uri.EscapeDataString(accountCode) + "/invoices");
         }
 
         public static RecurlyList<Invoice> List()
@@ -504,7 +504,7 @@
             var invoice = new Invoice();
 
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
-                "/accounts/" + Uri.EscapeUriString(accountCode) + Invoice.UrlPrefix,
+                "/accounts/" + Uri.EscapeDataString(accountCode) + Invoice.UrlPrefix,
                 invoice.ReadXml);
 
             return (int)statusCode == ValidationException.HttpStatusCode ? null : invoice;
```
