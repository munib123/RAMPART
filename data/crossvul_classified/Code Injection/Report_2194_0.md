# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in csharp
**Pair ID:** 2194_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2194_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```csharp
Lines 122-162 of the vulnerable file.

        /// <param name="renew">
        /// Whether or not renewed credentials are required.  If True, ticket validation
        /// will fail for Single Sign On credentials.
        /// </param>
        /// <param name="gateway">
        /// whether or not to include gatewayResponse=true in the request (client specific).
        /// </param>
        /// <param name="customParameters">custom parameters to add to the validation URL</param>
        /// <returns>The service ticket validation URL to use</returns>
        public static string ConstructValidateUrl(string serviceTicket, bool gateway, bool renew, NameValueCollection customParameters)
        {
            if (gateway && renew)
            {
                throw new ArgumentException("Gateway and Renew parameters are mutually exclusive and cannot both be True");
            }

            CasAuthentication.Initialize();

            EnhancedUriBuilder ub = new EnhancedUriBuilder(EnhancedUriBuilder.Combine(CasAuthentication.CasServerUrlPrefix, CasAuthentication.TicketValidator.UrlSuffix));
            ub.QueryItems.Add(CasAuthentication.TicketValidator.ServiceParameterName, HttpUtility.UrlEncode(ConstructServiceUrl(gateway)));
            ub.QueryItems.Add(CasAuthentication.TicketValidator.ArtifactParameterName, serviceTicket);

            if (renew)
            {
                ub.QueryItems.Set("renew", "true");
            }

            if (customParameters != null)
            {
                for (int i = 0; i < customParameters.Count; i++)
                {
                    string key = customParameters.AllKeys[i];
                    string value = customParameters[i];

                    ub.QueryItems.Add(key, value);
                }
            }
            return ub.Uri.AbsoluteUri;
        }

        /// <summary>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -139,7 +139,7 @@
 
             EnhancedUriBuilder ub = new EnhancedUriBuilder(EnhancedUriBuilder.Combine(CasAuthentication.CasServerUrlPrefix, CasAuthentication.TicketValidator.UrlSuffix));
             ub.QueryItems.Add(CasAuthentication.TicketValidator.ServiceParameterName, HttpUtility.UrlEncode(ConstructServiceUrl(gateway)));
-            ub.QueryItems.Add(CasAuthentication.TicketValidator.ArtifactParameterName, serviceTicket);
+            ub.QueryItems.Add(CasAuthentication.TicketValidator.ArtifactParameterName, HttpUtility.UrlEncode(serviceTicket));
 
             if (renew)
             {
```
