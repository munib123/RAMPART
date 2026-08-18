# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in csharp
**Pair ID:** 1815_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1815_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```csharp
Lines 1-38 of the vulnerable file.

﻿using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Mvc;
using Umbraco.Core;
using Umbraco.Core.Models;
using Umbraco.Core.Publishing;
using Umbraco.Core.Services;
using Umbraco.Web.Mvc;
using umbraco;
using umbraco.cms.businesslogic.web;

namespace Umbraco.Web.WebServices
{
    /// <summary>
    /// A REST controller used for the publish dialog in order to publish bulk items at once
    /// </summary>
    public class BulkPublishController : UmbracoAuthorizedController
    {
        /// <summary>
        /// Publishes an document
        /// </summary>
        /// <param name="documentId"></param>
        /// <param name="publishDescendants">true to publish descendants as well</param>
        /// <param name="includeUnpublished">true to publish documents that are unpublished</param>
        /// <returns>A Json array containing objects with the child id's of the document and it's current published status</returns>
        [HttpPost]
        public JsonResult PublishDocument(int documentId, bool publishDescendants, bool includeUnpublished)
        {
            var content = Services.ContentService.GetById(documentId);
            var doc = new Document(content);
            //var contentService = (ContentService) Services.ContentService;
            if (publishDescendants == false)
            {
                //var result = contentService.SaveAndPublishInternal(content);
                var result = doc.SaveAndPublish(UmbracoUser.Id);
                return Json(new
                    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,7 @@
     /// <summary>
     /// A REST controller used for the publish dialog in order to publish bulk items at once
     /// </summary>
+    [ValidateMvcAngularAntiForgeryToken]
     public class BulkPublishController : UmbracoAuthorizedController
     {
         /// <summary>
```
