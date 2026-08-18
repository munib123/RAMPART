# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in csharp
**Pair ID:** 1815_7
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1815_7`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```csharp
Lines 9-49 of the vulnerable file.

using Umbraco.Core.Services;
using Umbraco.Web.Macros;
using Umbraco.Web.Mvc;
using umbraco;
using umbraco.cms.businesslogic.macro;
using System.Collections.Generic;
using umbraco.cms.helpers;
using Umbraco.Core;
using Umbraco.Core.Configuration;
using Template = umbraco.cms.businesslogic.template.Template;

namespace Umbraco.Web.WebServices
{
    /// <summary>
    /// A REST controller used to save files such as templates, partial views, macro files, etc...
    /// </summary>
    /// <remarks>
    /// This isn't fully implemented yet but we should migrate all of the logic in the umbraco.presentation.webservices.codeEditorSave
    /// over to this controller.
    /// </remarks>
    public class SaveFileController : UmbracoAuthorizedController
    {
        /// <summary>
        /// Saves a partial view macro
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="oldName"></param>
        /// <param name="contents"></param>
        /// <returns></returns>
        [HttpPost]
        public JsonResult SavePartialViewMacro(string filename, string oldName, string contents)
        {
            var svce = (FileService) Services.FileService;

            return SavePartialView(svce,
                filename, oldName, contents,
                "MacroPartials/",
                (s, n) => s.GetPartialViewMacro(n),
                (s, v) => s.ValidatePartialViewMacro((PartialView) v),
                (s, v) => s.SavePartialViewMacro(v));
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,7 @@
     /// This isn't fully implemented yet but we should migrate all of the logic in the umbraco.presentation.webservices.codeEditorSave
     /// over to this controller.
     /// </remarks>
+    [ValidateMvcAngularAntiForgeryToken]
     public class SaveFileController : UmbracoAuthorizedController
     {
         /// <summary>
```
