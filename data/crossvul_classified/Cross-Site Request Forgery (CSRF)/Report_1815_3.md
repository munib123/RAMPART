# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in csharp
**Pair ID:** 1815_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1815_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```csharp
Lines 1-22 of the vulnerable file.

﻿using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Web.Helpers;
using Umbraco.Core;
using Umbraco.Core.Logging;

namespace Umbraco.Web.WebApi.Filters
{
    /// <summary>
    /// A helper class to deal with csrf prevention with angularjs and webapi
    /// </summary>
    public static class AngularAntiForgeryHelper
    {
        /// <summary>
        /// The cookie name that is used to store the validation value
        /// </summary>
        public const string CsrfValidationCookieName = "XSRF-V";

        /// <summary>
        /// The cookie name that is set for angular to use to pass in to the header value for "X-XSRF-TOKEN"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,6 @@
 ﻿using System;
+using System.Collections.Generic;
+using System.Collections.Specialized;
 using System.Linq;
 using System.Net.Http;
 using System.Net.Http.Headers;
@@ -27,6 +29,8 @@
         /// The header name that angular uses to pass in the token to validate the cookie
         /// </summary>
         public const string AngularHeadername = "X-XSRF-TOKEN";
+
+        
 
         /// <summary>
         /// Returns 2 tokens - one for the cookie value and one that angular should set as the header value
@@ -64,13 +68,10 @@
             return true;
         }
 
-        /// <summary>
-        /// Validates the headers/cookies passed in for the request
-        /// </summary>
-        /// <param name="requestHeaders"></param>
-        /// <param name="failedReason"></param>
-        /// <returns></returns>
-        public static bool ValidateHeaders(HttpRequestHeaders requestHeaders, out string failedReason)
+        internal static bool ValidateHeaders(            
+            KeyValuePair<string, IEnumerable<string>>[] requestHeaders, 
+            string cookieToken,
+            out string failedReason)
         {
             failedReason = "";
 
@@ -85,12 +86,7 @@
                 .Select(z => z.Value)
                 .SelectMany(z => z)
                 .FirstOrDefault();
-
-            var cookieToken = requestHeaders
-                .GetCookies()
-                .Select(c => c[CsrfValidationCookieName])
-                .FirstOrDefault();
-
+            
             // both header and cookie must be there
             if (cookieToken == null || headerToken == null)
             {
@@ -98,13 +94,32 @@
                 return false;
             }
 
-            if (ValidateTokens(cookieToken.Value, headerToken) == false)
+            if (ValidateTokens(cookieToken, headerToken) == false)
             {
                 failedReason = "Invalid token";
                 return false;
             }
-            
+
             return true;
+        }
+
+        /// <summary>
+        /// Validates the headers/cookies passed in for the request
+        /// </summary>
+        /// <param name="requestHeaders"></param>
+        /// <param name="failedReason"></param>
+        /// <returns></returns>
+        public static bool ValidateHeaders(HttpRequestHeaders requestHeaders, out string failedReason)
+        {
+            var cookieToken = requestHeaders
+                .GetCookies()
+                .Select(c => c[CsrfValidationCookieName])
+                .FirstOrDefault();
+
+            return ValidateHeaders(
+                requestHeaders.ToDictionary(x => x.Key, x => x.Value).ToArray(),
+                cookieToken == null ? null : cookieToken.Value,
+                out failedReason);
         }
     }
 }
```
