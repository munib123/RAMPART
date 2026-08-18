# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in csharp
**Pair ID:** 678_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `678_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```csharp
Lines 1-38 of the vulnerable file.

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using IdentityServer4.Services;
using IdentityServer4.Configuration;
using IdentityServer4.Stores;
using IdentityServer4.ResponseHandling;
using Microsoft.AspNetCore.Authentication;

namespace IdentityServer4.Endpoints.Results
{
    internal class AuthorizeResult : IEndpointResult
    {
        public AuthorizeResponse Response { get; }

        public AuthorizeResult(AuthorizeResponse response)
        {
            Response = response ?? throw new ArgumentNullException(nameof(response));
        }

        internal AuthorizeResult(
            AuthorizeResponse response,
            IdentityServerOptions options,
            IUserSession userSession,
            IMessageStore<ErrorMessage> errorMessageStore,
            ISystemClock clock)
            : this(response)
        {
            _options = options;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,7 @@
 using IdentityServer4.Stores;
 using IdentityServer4.ResponseHandling;
 using Microsoft.AspNetCore.Authentication;
+using System.Text.Encodings.Web;
 
 namespace IdentityServer4.Endpoints.Results
 {
@@ -175,7 +176,9 @@
         {
             var html = FormPostHtml;
 
-            html = html.Replace("{uri}", Response.Request.RedirectUri);
+            var url = Response.Request.RedirectUri;
+            url = HtmlEncoder.Default.Encode(url);
+            html = html.Replace("{uri}", url);
             html = html.Replace("{body}", Response.ToNameValueCollection().ToFormPost());
 
             return html;
```
