# CrossVul Fix Pair: Improper Input Validation in csharp
**Pair ID:** 869_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `869_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```csharp
Lines 1-30 of the vulnerable file.

﻿using Core.Data;
using Core.Helpers;
using Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;

namespace Core.Api
{
    [Route("api/[controller]")]
    [ApiController]
    public class AssetsController : ControllerBase
    {
        IDataService _data;
        IStorageService _store;

        public AssetsController(IDataService data, IStorageService store)
        {
            _data = data;
            _store = store;
        }

        /// <summary>
        /// Get list of assets - user saved images and files
        /// </summary>
        /// <param name="page">Page number</param>
        /// <param name="filter">filterImages or filterAttachments</param>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,7 @@
 using System.Collections.Generic;
 using System.Threading.Tasks;
 using System.Linq;
+using Microsoft.AspNetCore.Authorization;
 
 namespace Core.Api
 {
@@ -40,20 +41,20 @@
             {
                 if (filter == "filterImages")
                 {
-                    items = await _store.Find(a => a.AssetType == AssetType.Image, pager);
+                    items = await _store.Find(a => a.AssetType == AssetType.Image, pager, "", !User.Identity.IsAuthenticated);
                 }
                 else if (filter == "filterAttachments")
                 {
-                    items = await _store.Find(a => a.AssetType == AssetType.Attachment, pager);
+                    items = await _store.Find(a => a.AssetType == AssetType.Attachment, pager, "", !User.Identity.IsAuthenticated);
                 }
                 else
                 {
-                    items = await _store.Find(null, pager);
+                    items = await _store.Find(null, pager, "", !User.Identity.IsAuthenticated);
                 }
             }
             else
             {
-                items = await _store.Find(a => a.Title.Contains(search), pager);
+                items = await _store.Find(a => a.Title.Contains(search), pager, "", !User.Identity.IsAuthenticated);
             }
 
             if (page < 1 || page > pager.LastPage)
@@ -110,11 +111,12 @@
         }
 
         /// <summary>
-        /// Upload file(s) to user data store
+        /// Upload file(s) to user data store, authentication required
         /// </summary>
         /// <param name="files">Selected files</param>
         /// <returns>Success or internal error</returns>
         [HttpPost("upload")]
+        [Authorize]
         public async Task<IActionResult> Upload(ICollection<IFormFile> files)
         {
             try
@@ -137,6 +139,7 @@
         /// <param name="url">Relative URL of the file to remove</param>
         /// <returns></returns>
         [HttpDelete("remove")]
+        [Authorize]
         public IActionResult Remove(string url)
         {
             try
```
