# CrossVul Fix Pair: Creation of Temporary File in Directory with Insecure Permissions in java
**Pair ID:** 1927_9
**Vulnerability Class:** Creation of Temporary File in Directory with Insecure Permissions
**CWE:** CWE-379
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1927_9`)

## Vulnerability Information & PoC

## Description
Creation of Temporary File in Directory with Insecure Permissions - On some operating systems, the fact that the temporary file exists may be apparent to any user with sufficient privileges to access that directory.

## Vulnerable Code
```java
Lines 3-43 of the vulnerable file.

 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package io.netty.handler.ssl.util;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.base64.Base64;
import io.netty.util.CharsetUtil;
import io.netty.util.internal.SystemPropertyUtil;
import io.netty.util.internal.ThrowableUtil;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,7 @@
 import io.netty.buffer.Unpooled;
 import io.netty.handler.codec.base64.Base64;
 import io.netty.util.CharsetUtil;
+import io.netty.util.internal.PlatformDependent;
 import io.netty.util.internal.SystemPropertyUtil;
 import io.netty.util.internal.ThrowableUtil;
 import io.netty.util.internal.logging.InternalLogger;
@@ -30,6 +31,7 @@
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.io.OutputStream;
+import java.nio.file.Files;
 import java.security.KeyPair;
 import java.security.KeyPairGenerator;
 import java.security.NoSuchAlgorithmException;
@@ -330,7 +332,7 @@
             wrappedBuf.release();
         }
 
-        File keyFile = File.createTempFile("keyutil_" + fqdn + '_', ".key");
+        File keyFile = PlatformDependent.createTempFile("keyutil_" + fqdn + '_', ".key", null);
         keyFile.deleteOnExit();
 
         OutputStream keyOut = new FileOutputStream(keyFile);
@@ -361,7 +363,7 @@
             wrappedBuf.release();
         }
 
-        File certFile = File.createTempFile("keyutil_" + fqdn + '_', ".crt");
+        File certFile = PlatformDependent.createTempFile("keyutil_" + fqdn + '_', ".crt", null);
         certFile.deleteOnExit();
 
         OutputStream certOut = new FileOutputStream(certFile);
```
