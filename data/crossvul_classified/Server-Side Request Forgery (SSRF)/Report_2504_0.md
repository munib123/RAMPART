# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2504_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2504_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 128-168 of the vulnerable file.


        internal Account(XmlTextReader xmlReader)
        {
            ReadXml(xmlReader);
        }

        internal Account(XmlTextReader xmlReader, string xmlName)
        {
            ReadXml(xmlReader, xmlName);
        }

        internal Account()
        { }

        /// <summary>
        /// Delete an account's billing info.
        /// </summary>
        public void DeleteBillingInfo()
        {
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Delete,
                UrlPrefix + Uri.EscapeUriString(AccountCode) + "/billing_info");
            _billingInfo = null;
        }

        /// <summary>
        /// Create a new account in Recurly
        /// </summary>
        public void Create()
        {
            // POST /accounts
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Post, UrlPrefix, WriteXml, ReadXml);
        }

        /// <summary>
        /// Update an existing account in Recurly
        /// </summary>
        public void Update()
        {
            // PUT /accounts/<account code>
            Client.Instance.PerformRequest(Client.HttpRequestMethod.Put,
                UrlPrefix + Uri.EscapeUriString(AccountCode),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -145,7 +145,7 @@
         public void DeleteBillingInfo()
         {
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Delete,
-                UrlPrefix + Uri.EscapeUriString(AccountCode) + "/billing_info");
+                UrlPrefix + Uri.EscapeDataString(AccountCode) + "/billing_info");
             _billingInfo = null;
         }
 
@@ -165,7 +165,7 @@
         {
             // PUT /accounts/<account code>
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Put,
-                UrlPrefix + Uri.EscapeUriString(AccountCode),
+                UrlPrefix + Uri.EscapeDataString(AccountCode),
                 WriteXml);
         }
 
@@ -199,7 +199,7 @@
         {
             var i = invoice ?? new Invoice();
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
-                UrlPrefix + Uri.EscapeUriString(AccountCode) + "/invoices",
+                UrlPrefix + Uri.EscapeDataString(AccountCode) + "/invoices",
                 i.WriteXml,
                 i.ReadXml);
 
@@ -213,7 +213,7 @@
         {
             var i = invoice ?? new Invoice();
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Post,
-                UrlPrefix + Uri.EscapeUriString(AccountCode) + "/invoices/preview",
+                UrlPrefix + Uri.EscapeDataString(AccountCode) + "/invoices/preview",
                 i.WriteXml,
                 i.ReadXml);
 
@@ -231,7 +231,7 @@
         {
             var adjustments = new AdjustmentList();
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
-                UrlPrefix + Uri.EscapeUriString(AccountCode) + "/adjustments/"
+                UrlPrefix + Uri.EscapeDataString(AccountCode) + "/adjustments/"
                 + Build.QueryStringWith(Adjustment.AdjustmentState.Any == state ? "" : "state=" + state.ToString().EnumNameToTransportCase())
                 .AndWith(Adjustment.AdjustmentType.All == type ? "" : "type=" + type.ToString().EnumNameToTransportCase())
                 , adjustments.ReadXmlList);
@@ -247,7 +247,7 @@
         {
             var shippingAddresses = new ShippingAddressList(this);
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
-                UrlPrefix + Uri.EscapeUriString(AccountCode) + "/shipping_addresses/",
+                UrlPrefix + Uri.EscapeDataString(AccountCode) + "/shipping_addresses/",
                 shippingAddresses.ReadXmlList);
 
             return statusCode == HttpStatusCode.NotFound ? null : shippingAddresses;
@@ -269,7 +269,7 @@
         /// <returns></returns>
         public RecurlyList<Subscription> GetSubscriptions(Subscription.SubscriptionState state = Subscription.SubscriptionState.All)
         {
-            return new SubscriptionList(UrlPrefix + Uri.EscapeUriString(AccountCode) + "/subscriptions/"
+            return new SubscriptionList(UrlPrefix + Uri.EscapeDataString(AccountCode) + "/subscriptions/"
                 + Build.QueryStringWith(state.Equals(Subscription.SubscriptionState.All) ? "" : "state=" + state.ToString().EnumNameToTransportCase()));
         }
 
@@ -282,14 +282,14 @@
         public RecurlyList<Transaction> GetTransactions(TransactionList.TransactionState state = TransactionList.TransactionState.All,
             TransactionList.TransactionType type = TransactionList.TransactionType.All)
         {
-            return new TransactionList(UrlPrefix + Uri.EscapeUriString(AccountCode) + "/transactions/"
+            return new TransactionList(UrlPrefix + Uri.EscapeDataString(AccountCode) + "/transactions/"
                  + Build.QueryStringWith(state != TransactionList.TransactionState.All ? "state=" + state.ToString().EnumNameToTransportCase() : "")
                    .AndWith(type != TransactionList.TransactionType.All ? "type=" + type.ToString().EnumNameToTransportCase() : ""));
         }
 
         public RecurlyList<Note> GetNotes()
         {
-            return new NoteList(UrlPrefix + Uri.EscapeUriString(AccountCode) + "/notes/");
+            return new NoteList(UrlPrefix + Uri.EscapeDataString(AccountCode) + "/notes/");
         }
 
         /// <summary>
@@ -328,7 +328,7 @@
             var redemptions = new CouponRedemptionList();
 
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
-                UrlPrefix + Uri.EscapeUriString(AccountCode) + "/redemptions",
+                UrlPrefix + Uri.EscapeDataString(AccountCode) + "/redemptions",
                 redemptions.ReadXmlList);
 
             return statusCode == HttpStatusCode.NotFound ? null : redemptions;
@@ -560,7 +560,7 @@
             var account = new Account();
             // GET /accounts/<account code>
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
-                UrlPrefix + Uri.EscapeUriString(accountCode),
+                UrlPrefix + Uri.EscapeDataString(accountCode),
                 account.ReadXml);
 
             return statusCode == HttpStatusCode.NotFound ? null : account;
@@ -575,7 +575,7 @@
         {
             // DELETE /accounts/<account code>
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Delete,
-                Account.UrlPrefix + Uri.EscapeUriString(accountCode));
+                Account.UrlPrefix + Uri.EscapeDataString(accountCode));
         }
 
         /// <summary>
@@ -586,7 +586,7 @@
         {
             // PUT /accounts/<account code>/reopen
             Client.Instance.PerformRequest(Client.HttpRequestMethod.Put,
-                Account.UrlPrefix + Uri.EscapeUriString(accountCode) + "/reopen");
+                Account.UrlPrefix + Uri.EscapeDataString(accountCode) + "/reopen");
         }
 
         /// <summary>
```
