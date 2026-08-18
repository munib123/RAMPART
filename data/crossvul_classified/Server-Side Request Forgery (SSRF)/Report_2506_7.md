# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2506_7
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2506_7`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 1-21 of the vulnerable file.

﻿using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using DNN.Integration.Test.Framework;
using DNN.Integration.Test.Framework.Helpers;
using NUnit.Framework;

namespace DotNetNuke.Tests.Integration.Tests.Security
{
    [TestFixture]
    public class AuthCookieTests : IntegrationTestBase
    {
        private const string GetPortaslApi = "/API/PersonaBar/SiteSettings/GetPortals";

        [Test]
        public void Using_Logged_Out_Cookie_Should_Be_Unauthorized()
        {
            var session = WebApiTestHelper.LoginHost();
            Assert.IsTrue(session.IsLoggedIn);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,10 @@
-﻿using System;
+﻿// DotNetNuke® - http://www.dnnsoftware.com
+// Copyright (c) 2002-2018, DNN Corp.
+// All Rights Reserved
+
+using System;
 using System.Net;
 using System.Net.Http;
-using System.Net.Http.Headers;
-using System.Threading;
 using DNN.Integration.Test.Framework;
 using DNN.Integration.Test.Framework.Helpers;
 using NUnit.Framework;
```
