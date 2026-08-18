# CrossVul Fix Pair: Authentication Bypass by Capture-replay in csharp
**Pair ID:** 4558_0
**Vulnerability Class:** Authentication Bypass by Capture-replay
**CWE:** CWE-294
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4558_0`)

## Vulnerability Information & PoC

## Description
Authentication Bypass by Capture-replay - Capture-replay attacks are common and can be difficult to defeat without cryptography.

## Vulnerable Code
```csharp
Lines 1-21 of the vulnerable file.

﻿using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Saml2P;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Sustainsys.Saml2.Configuration
{
    /// <summary>
    /// Options for the service provider's behaviour; i.e. everything except
    /// the idp and federation list.
    /// </summary>
    public class SPOptions
    {
        /// <summary>
        /// Ctor
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,7 @@
-﻿using Sustainsys.Saml2.Metadata;
+﻿using Microsoft.IdentityModel.Tokens;
+using Sustainsys.Saml2.Metadata;
 using Sustainsys.Saml2.Saml2P;
+using Sustainsys.Saml2.Tokens;
 using System;
 using System.Collections.Concurrent;
 using System.Collections.Generic;
@@ -22,7 +24,7 @@
         /// </summary>
         public SPOptions()
         {
-			MetadataCacheDuration = new XsdDuration(hours: 1);
+            MetadataCacheDuration = new XsdDuration(hours: 1);
             Compatibility = new Compatibility();
             OutboundSigningAlgorithm = XmlHelpers.GetDefaultSigningAlgorithmName();
             MinIncomingSigningAlgorithm = XmlHelpers.GetDefaultSigningAlgorithmName();
@@ -102,7 +104,7 @@
                 // Capture in a local variable to prevent race conditions. Reads and writes
                 // of references are atomic so there is no need for a lock.
                 var value = saml2PSecurityTokenHandler;
-                if(value == null)
+                if (value == null)
                 {
                     // Set the saved value, but don't trust it - still use a local var for the return.
                     saml2PSecurityTokenHandler = value = new Saml2PSecurityTokenHandler(this);
@@ -112,7 +114,7 @@
             }
             set
             {
-                saml2PSecurityTokenHandler = value; 
+                saml2PSecurityTokenHandler = value;
             }
         }
 
@@ -135,7 +137,7 @@
             }
             set
             {
-                if(saml2PSecurityTokenHandler != null)
+                if (saml2PSecurityTokenHandler != null)
                 {
                     throw new InvalidOperationException("Can't change entity id when a token handler has been instantiated.");
                 }
@@ -157,7 +159,7 @@
             }
             set
             {
-                if(value == null)
+                if (value == null)
                 {
                     throw new ArgumentNullException(nameof(value));
                 }
@@ -212,7 +214,7 @@
         }
 
         readonly ICollection<AttributeConsumingService> attributeConsumingServices
-			= new List<AttributeConsumingService>();
+            = new List<AttributeConsumingService>();
 
         /// <summary>
         /// Collection of attribute consuming services for the service provider.
@@ -292,7 +294,7 @@
                 var futureBothCertExists = metaDataCertificates
                     .Any(c => c.Status == CertificateStatus.Future && c.Use == CertificateUse.Both);
 
-                foreach(var cert in metaDataCertificates)
+                foreach (var cert in metaDataCertificates)
                 {
                     // Just like we stop publishing Encryption cert immediately when a Future one is added,
                     // in the case of a "Both" cert we should switch the current use to Signing so that Idp's stop sending
@@ -358,7 +360,7 @@
         /// overriden for each <see cref="IdentityProvider"/>.
         /// </summary>
         public string OutboundSigningAlgorithm { get; set; }
-        
+
         /// <summary>
         /// Metadata flag that we want assertions to be signed.
         /// </summary>
@@ -379,7 +381,7 @@
         public Compatibility Compatibility { get; set; }
 
         private string minIncomingSigningAlgorithm;
-        
+
         /// <summary>
         /// Minimum accepted signature algorithm for any incoming messages.
         /// </summary>
@@ -391,7 +393,7 @@
             }
             set
             {
-                if(!XmlHelpers.KnownSigningAlgorithms.Contains(value))
+                if (!XmlHelpers.KnownSigningAlgorithms.Contains(value))
                 {
                     throw new ArgumentException("The signing algorithm " + value +
                         " is unknown or not supported by the current .NET Framework.");
@@ -404,5 +406,22 @@
         /// Adapter to logging framework of hosting application.
         /// </summary>
         public ILoggerAdapter Logger { get; set; }
-    }
+
+        private ITokenReplayCache tokenReplayCache;
+        public ITokenReplayCache TokenReplayCache 
+        { 
+            get
+            {
+                if(tokenReplayCache == null)
+                {
+                    tokenReplayCache = new TokenReplayCache();
+                }
+                return tokenReplayCache;
+            }
+            set
+            {
+                tokenReplayCache = value;
+            }
+        }
 }
+}
```
