# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2504_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2504_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 2-42 of the vulnerable file.

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Recurly
{
    public class AccountBalance : RecurlyEntity
    {
        public bool PastDue { get; internal set; }
        public Dictionary<string, int> BalanceInCents = new Dictionary<string, int>();
        private const string UrlPrefix = "/accounts/";

        public static AccountBalance Get(string accountCode)
        {
            var accountBalance = new AccountBalance();

            var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
                UrlPrefix + Uri.EscapeUriString(accountCode) + "/balance", accountBalance.ReadXml);

            return statusCode == HttpStatusCode.NotFound ? null : accountBalance;
        }

        internal override void ReadXml(XmlTextReader reader)
        {
            while (reader.Read())
            {
                if (reader.Name == "account_balance" && reader.NodeType == XmlNodeType.EndElement)
                    break;

                if (reader.NodeType != XmlNodeType.Element) continue;

                switch (reader.Name)
                {
                    case "past_due":
                        bool b;
                        if (bool.TryParse(reader.ReadElementContentAsString(), out b))
                            PastDue = b;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,7 +19,7 @@
             var accountBalance = new AccountBalance();
 
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
-                UrlPrefix + Uri.EscapeUriString(accountCode) + "/balance", accountBalance.ReadXml);
+                UrlPrefix + Uri.EscapeDataString(accountCode) + "/balance", accountBalance.ReadXml);
 
             return statusCode == HttpStatusCode.NotFound ? null : accountBalance;
         }
```
