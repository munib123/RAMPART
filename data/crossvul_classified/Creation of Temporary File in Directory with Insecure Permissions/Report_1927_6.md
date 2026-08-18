# CrossVul Fix Pair: Creation of Temporary File in Directory with Insecure Permissions in java
**Pair ID:** 1927_6
**Vulnerability Class:** Creation of Temporary File in Directory with Insecure Permissions
**CWE:** CWE-379
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1927_6`)

## Vulnerability Information & PoC

## Description
Creation of Temporary File in Directory with Insecure Permissions - On some operating systems, the fact that the temporary file exists may be apparent to any user with sufficient privileges to access that directory.

## Vulnerable Code
```java
Lines 256-296 of the vulnerable file.

            f1.delete();
            assertNull(f1.getFile());
            assertNotNull(tmpFile);
            assertFalse(tmpFile.exists());
        }
    }

    @Test
    public void setSetContentFromFileExceptionally() throws Exception {
        final long maxSize = 4;
        DiskFileUpload f1 = new DiskFileUpload("file5", "file5", "application/json", null, null, 0);
        f1.setMaxSize(maxSize);
        try {
            f1.setContent(Unpooled.wrappedBuffer(new byte[(int) maxSize]));
            File originalFile = f1.getFile();
            assertNotNull(originalFile);
            assertEquals(maxSize, originalFile.length());
            assertEquals(maxSize, f1.length());
            byte[] bytes = new byte[8];
            PlatformDependent.threadLocalRandom().nextBytes(bytes);
            File tmpFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
            tmpFile.deleteOnExit();
            FileOutputStream fos = new FileOutputStream(tmpFile);
            try {
                fos.write(bytes);
                fos.flush();
            } finally {
                fos.close();
            }
            try {
                f1.setContent(tmpFile);
                fail("should not reach here!");
            } catch (IOException e) {
                assertNotNull(f1.getFile());
                assertEquals(originalFile, f1.getFile());
                assertEquals(maxSize, f1.length());
            }
        } finally {
            f1.delete();
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -273,7 +273,7 @@
             assertEquals(maxSize, f1.length());
             byte[] bytes = new byte[8];
             PlatformDependent.threadLocalRandom().nextBytes(bytes);
-            File tmpFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
+            File tmpFile = PlatformDependent.createTempFile(UUID.randomUUID().toString(), ".tmp", null);
             tmpFile.deleteOnExit();
             FileOutputStream fos = new FileOutputStream(tmpFile);
             try {
```
