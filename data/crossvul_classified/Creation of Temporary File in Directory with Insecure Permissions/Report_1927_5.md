# CrossVul Fix Pair: Creation of Temporary File in Directory with Insecure Permissions in java
**Pair ID:** 1927_5
**Vulnerability Class:** Creation of Temporary File in Directory with Insecure Permissions
**CWE:** CWE-379
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1927_5`)

## Vulnerability Information & PoC

## Description
Creation of Temporary File in Directory with Insecure Permissions - On some operating systems, the fact that the temporary file exists may be apparent to any user with sufficient privileges to access that directory.

## Vulnerable Code
```java
Lines 26-66 of the vulnerable file.

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.UUID;

import static io.netty.util.CharsetUtil.*;
import static org.junit.Assert.*;

/** {@link AbstractMemoryHttpData} test cases. */
public class AbstractMemoryHttpDataTest {

    @Test
    public void testSetContentFromFile() throws Exception {
        TestHttpData test = new TestHttpData("test", UTF_8, 0);
        try {
            File tmpFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
            tmpFile.deleteOnExit();
            FileOutputStream fos = new FileOutputStream(tmpFile);
            byte[] bytes = new byte[4096];
            PlatformDependent.threadLocalRandom().nextBytes(bytes);
            try {
                fos.write(bytes);
                fos.flush();
            } finally {
                fos.close();
            }
            test.setContent(tmpFile);
            ByteBuf buf = test.getByteBuf();
            assertEquals(buf.readerIndex(), 0);
            assertEquals(buf.writerIndex(), bytes.length);
            assertArrayEquals(bytes, test.get());
            assertArrayEquals(bytes, ByteBufUtil.getBytes(buf));
        } finally {
            //release the ByteBuf
            test.delete();
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,7 @@
     public void testSetContentFromFile() throws Exception {
         TestHttpData test = new TestHttpData("test", UTF_8, 0);
         try {
-            File tmpFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
+            File tmpFile = PlatformDependent.createTempFile(UUID.randomUUID().toString(), ".tmp", null);
             tmpFile.deleteOnExit();
             FileOutputStream fos = new FileOutputStream(tmpFile);
             byte[] bytes = new byte[4096];
@@ -70,7 +70,7 @@
     public void testRenameTo() throws Exception {
         TestHttpData test = new TestHttpData("test", UTF_8, 0);
         try {
-            File tmpFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
+            File tmpFile = PlatformDependent.createTempFile(UUID.randomUUID().toString(), ".tmp", null);
             tmpFile.deleteOnExit();
             final int totalByteCount = 4096;
             byte[] bytes = new byte[totalByteCount];
```
