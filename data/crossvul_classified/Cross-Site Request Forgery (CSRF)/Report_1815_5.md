# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in csharp
**Pair ID:** 1815_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1815_5`)

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
using System.Text;
using System.Web.Http;
using System.Web.Services.Description;
using Umbraco.Core;
using Umbraco.Core.Models;
using Umbraco.Web.Routing;
using Umbraco.Web.WebApi;
//using umbraco.cms.businesslogic.language;
using umbraco.BusinessLogic.Actions;
using umbraco.cms.businesslogic.web;

namespace Umbraco.Web.WebServices
{
    /// <summary>
    /// A REST controller used for managing domains.
    /// </summary>
    /// <remarks>Nothing to do with Active Directory.</remarks>
    public class DomainsApiController : UmbracoAuthorizedApiController
    {
        [HttpPost]
        // can't pass multiple complex args in json post request...
        public PostBackModel SaveLanguageAndDomains(PostBackModel model)
        {
            var node = ApplicationContext.Current.Services.ContentService.GetById(model.NodeId);

            if (node == null)
            {
                var response = Request.CreateResponse(HttpStatusCode.BadRequest);
                response.Content = new StringContent(string.Format("There is no content node with id {0}.", model.NodeId));
                response.ReasonPhrase = "Node Not Found.";
                throw new HttpResponseException(response);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,7 @@
 //using umbraco.cms.businesslogic.language;
 using umbraco.BusinessLogic.Actions;
 using umbraco.cms.businesslogic.web;
+using Umbraco.Web.WebApi.Filters;
 
 namespace Umbraco.Web.WebServices
 {
@@ -20,6 +21,7 @@
     /// A REST controller used for managing domains.
     /// </summary>
     /// <remarks>Nothing to do with Active Directory.</remarks>
+    [ValidateAngularAntiForgeryToken]
     public class DomainsApiController : UmbracoAuthorizedApiController
     {
         [HttpPost]
```
