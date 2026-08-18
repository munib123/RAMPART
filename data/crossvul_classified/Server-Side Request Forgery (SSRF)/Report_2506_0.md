# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2506_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2506_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 1-22 of the vulnerable file.

﻿using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Web;
using DotNetNuke.Common;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Services.FileSystem;
using DotNetNuke.Services.GeneratedImage.FilterTransform;
using DotNetNuke.Services.GeneratedImage.StartTransform;
using DotNetNuke.Services.Localization.Internal;
using Assembly = System.Reflection.Assembly;

namespace DotNetNuke.Services.GeneratedImage
{
    public class DnnImageHandler : ImageHandler
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 ﻿using System;
+using System.Collections.Generic;
 using System.Collections.Specialized;
 using System.Configuration;
 using System.Drawing;
@@ -233,11 +234,14 @@
                         }
                         else if (!string.IsNullOrEmpty(parameters["Url"]))
                         {
-                            if (!parameters["Url"].StartsWith("http"))
+                            var url = parameters["Url"];
+                            // allow only site resources when using the url parameter
+                            if (!url.StartsWith("http") || !UriBelongsToSite(new Uri(url)))
                             {
                                 return GetEmptyImageInfo();
                             }
-                            imgUrl = parameters["Url"];
+
+                            imgUrl = url;
                         }
 
                         if (string.IsNullOrEmpty(parameters["format"]))
@@ -555,5 +559,20 @@
                     return ImageFormat.Png;
             }
         }
+
+        // checks whether the uri belongs to any of the site-wide aliases
+        private static bool UriBelongsToSite(Uri uri)
+        {
+            IEnumerable<string> hostAliases =
+                from PortalAliasInfo alias in PortalAliasController.Instance.GetPortalAliases().Values
+                 select alias.HTTPAlias.ToLowerInvariant();
+
+            // if URI, for example, = "http(s)://myDomain:80/DNNDev/myPage?var=name" , then the two strings will be
+            // uriNoScheme1 = "mydomain/dnndev/mypage"  -- lower case
+            // uriNoScheme2 = "mydomain:80/dnndev/mypage"  -- lower case
+            var uriNoScheme1 = (uri.DnsSafeHost + uri.LocalPath).ToLowerInvariant();
+            var uriNoScheme2 = (uri.Authority + uri.LocalPath).ToLowerInvariant();
+            return hostAliases.Any(alias => uriNoScheme1.StartsWith(alias) || uriNoScheme2.StartsWith(alias));
+        }
     }
 }
```
