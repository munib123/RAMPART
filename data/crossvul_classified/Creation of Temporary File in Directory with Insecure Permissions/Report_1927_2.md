# CrossVul Fix Pair: Creation of Temporary File in Directory with Insecure Permissions in java
**Pair ID:** 1927_2
**Vulnerability Class:** Creation of Temporary File in Directory with Insecure Permissions
**CWE:** CWE-379
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1927_2`)

## Vulnerability Information & PoC

## Description
Creation of Temporary File in Directory with Insecure Permissions - On some operating systems, the fact that the temporary file exists may be apparent to any user with sufficient privileges to access that directory.

## Vulnerable Code
```java
Lines 2-42 of the vulnerable file.

 * Copyright 2012 The Netty Project
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
package io.netty.handler.codec.http.multipart;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.HttpConstants;
import io.netty.util.internal.EmptyArrays;
import io.netty.util.internal.ObjectUtil;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;

import static io.netty.buffer.Unpooled.EMPTY_BUFFER;
import static io.netty.buffer.Unpooled.wrappedBuffer;

/**
 * Abstract Disk HttpData implementation
 */
public abstract class AbstractDiskHttpData extends AbstractHttpData {

    private static final InternalLogger logger = InternalLoggerFactory.getInstance(AbstractDiskHttpData.class);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 import io.netty.handler.codec.http.HttpConstants;
 import io.netty.util.internal.EmptyArrays;
 import io.netty.util.internal.ObjectUtil;
+import io.netty.util.internal.PlatformDependent;
 import io.netty.util.internal.logging.InternalLogger;
 import io.netty.util.internal.logging.InternalLoggerFactory;
 
@@ -88,9 +89,9 @@
         File tmpFile;
         if (getBaseDirectory() == null) {
             // create a temporary file
-            tmpFile = File.createTempFile(getPrefix(), newpostfix);
+            tmpFile = PlatformDependent.createTempFile(getPrefix(), newpostfix, null);
         } else {
-            tmpFile = File.createTempFile(getPrefix(), newpostfix, new File(
+            tmpFile = PlatformDependent.createTempFile(getPrefix(), newpostfix, new File(
                     getBaseDirectory()));
         }
         if (deleteOnExit()) {
```
