# CrossVul Fix Pair: Improper Input Validation in xml
**Pair ID:** 869_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `869_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```xml
Lines 7-47 of the vulnerable file.

        <member name="M:Core.Api.AssetsController.Get(System.Int32,System.String,System.String)">
            <summary>
            Get list of assets - user saved images and files
            </summary>
            <param name="page">Page number</param>
            <param name="filter">filterImages or filterAttachments</param>
            <param name="search">Search term</param>
            <returns>Model containing collection of assets and Pager object</returns>
        </member>
        <member name="M:Core.Api.AssetsController.Pick(System.String,System.String,System.String)">
            <summary>
            Select an asset in the File Manager to include in the post
            </summary>
            <param name="type">Type of asset (post cover, logo, avatar or post image/attachment)</param>
            <param name="asset">Selected asset</param>
            <param name="post">Post ID</param>
            <returns>Asset Item</returns>
        </member>
        <member name="M:Core.Api.AssetsController.Upload(System.Collections.Generic.ICollection{Microsoft.AspNetCore.Http.IFormFile})">
            <summary>
            Upload file(s) to user data store
            </summary>
            <param name="files">Selected files</param>
            <returns>Success or internal error</returns>
        </member>
        <member name="M:Core.Api.AssetsController.Remove(System.String)">
            <summary>
            Remove file from user data store, authentication required
            </summary>
            <param name="url">Relative URL of the file to remove</param>
            <returns></returns>
        </member>
        <member name="M:Core.Api.AuthorsController.Get(System.Int32)">
            <summary>
            Get list of blog authors
            </summary>
            <param name="page">Page number</param>
            <returns>List of authors</returns>
        </member>
        <member name="M:Core.Api.AuthorsController.Get(System.String)">
            <summary>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,7 +24,7 @@
         </member>
         <member name="M:Core.Api.AssetsController.Upload(System.Collections.Generic.ICollection{Microsoft.AspNetCore.Http.IFormFile})">
             <summary>
-            Upload file(s) to user data store
+            Upload file(s) to user data store, authentication required
             </summary>
             <param name="files">Selected files</param>
             <returns>Success or internal error</returns>
```
