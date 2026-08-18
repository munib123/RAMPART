# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in csharp
**Pair ID:** 1815_6
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1815_6`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```csharp
Lines 1-36 of the vulnerable file.

﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Examine;
using Examine.LuceneEngine;
using Examine.LuceneEngine.Providers;
using Examine.Providers;
using Lucene.Net.Search;
using Umbraco.Core;
using Umbraco.Core.Logging;
using Umbraco.Web.Search;
using Umbraco.Web.WebApi;

namespace Umbraco.Web.WebServices
{
    public class ExamineManagementApiController : UmbracoAuthorizedApiController
    {
        /// <summary>
        /// Checks if the member internal index is consistent with the data stored in the database
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public bool CheckMembersInternalIndex()
        {
            var total = Services.MemberService.Count();

            var criteria = ExamineManager.Instance.SearchProviderCollection["InternalMemberSearcher"]
                .CreateSearchCriteria().RawQuery("__IndexType:member");
            var totalIndexed = ExamineManager.Instance.SearchProviderCollection["InternalMemberSearcher"].Search(criteria);

            return total == totalIndexed.TotalItemCount;
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,9 +13,11 @@
 using Umbraco.Core.Logging;
 using Umbraco.Web.Search;
 using Umbraco.Web.WebApi;
+using Umbraco.Web.WebApi.Filters;
 
 namespace Umbraco.Web.WebServices
 {
+    [ValidateAngularAntiForgeryToken]
     public class ExamineManagementApiController : UmbracoAuthorizedApiController
     {
         /// <summary>
```
