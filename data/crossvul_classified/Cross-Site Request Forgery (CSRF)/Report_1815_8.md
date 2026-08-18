# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in csharp
**Pair ID:** 1815_8
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1815_8`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```csharp
Lines 1-27 of the vulnerable file.

using System;
using System.Web.Http;
using Umbraco.Core;
using Umbraco.Core.Models.Rdbms;
using Umbraco.Core.Persistence;
using Umbraco.Web.WebApi;

namespace Umbraco.Web.WebServices
{

    public class XmlDataIntegrityController : UmbracoAuthorizedApiController
    {
        [HttpPost]
        public bool FixContentXmlTable()
        {
            Services.ContentService.RebuildXmlStructures();
            return CheckContentXmlTable();
        }

        [HttpPost]
        public bool FixMediaXmlTable()
        {
            Services.MediaService.RebuildXmlStructures();
            return CheckMediaXmlTable();
        }

        [HttpPost]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,10 +4,11 @@
 using Umbraco.Core.Models.Rdbms;
 using Umbraco.Core.Persistence;
 using Umbraco.Web.WebApi;
+using Umbraco.Web.WebApi.Filters;
 
 namespace Umbraco.Web.WebServices
 {
-
+    [ValidateAngularAntiForgeryToken]
     public class XmlDataIntegrityController : UmbracoAuthorizedApiController
     {
         [HttpPost]
```
