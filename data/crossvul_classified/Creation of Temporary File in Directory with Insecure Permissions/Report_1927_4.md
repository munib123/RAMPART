# CrossVul Fix Pair: Creation of Temporary File in Directory with Insecure Permissions in java
**Pair ID:** 1927_4
**Vulnerability Class:** Creation of Temporary File in Directory with Insecure Permissions
**CWE:** CWE-379
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1927_4`)

## Vulnerability Information & PoC

## Description
Creation of Temporary File in Directory with Insecure Permissions - On some operating systems, the fact that the temporary file exists may be apparent to any user with sufficient privileges to access that directory.

## Vulnerable Code
```java
Lines 22-62 of the vulnerable file.


import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.UUID;

import static io.netty.util.CharsetUtil.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/**
 * {@link AbstractDiskHttpData} test cases
 */
public class AbstractDiskHttpDataTest {

    @Test
    public void testGetChunk() throws Exception {
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
            ByteBuf buf1 = test.getChunk(1024);
            assertEquals(buf1.readerIndex(), 0);
            assertEquals(buf1.writerIndex(), 1024);
            ByteBuf buf2 = test.getChunk(1024);
            assertEquals(buf2.readerIndex(), 0);
            assertEquals(buf2.writerIndex(), 1024);
            assertFalse("Arrays should not be equal",
                    Arrays.equals(ByteBufUtil.getBytes(buf1), ByteBufUtil.getBytes(buf2)));
        } finally {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,7 @@
     public void testGetChunk() throws Exception {
         TestHttpData test = new TestHttpData("test", UTF_8, 0);
         try {
-            File tmpFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
+            File tmpFile = PlatformDependent.createTempFile(UUID.randomUUID().toString(), ".tmp", null);
             tmpFile.deleteOnExit();
             FileOutputStream fos = new FileOutputStream(tmpFile);
             byte[] bytes = new byte[4096];
```
