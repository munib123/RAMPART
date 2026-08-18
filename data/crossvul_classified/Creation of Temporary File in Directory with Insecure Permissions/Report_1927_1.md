# CrossVul Fix Pair: Creation of Temporary File in Directory with Insecure Permissions in java
**Pair ID:** 1927_1
**Vulnerability Class:** Creation of Temporary File in Directory with Insecure Permissions
**CWE:** CWE-379
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1927_1`)

## Vulnerability Information & PoC

## Description
Creation of Temporary File in Directory with Insecure Permissions - On some operating systems, the fact that the temporary file exists may be apparent to any user with sufficient privileges to access that directory.

## Vulnerable Code
```java
Lines 289-329 of the vulnerable file.


        buf.release();
    }

    @Test
    public void testWrapBufferRoundTrip() {
        ByteBuf buf = buffer(((ByteBuffer) allocate(16).putInt(1).putInt(2).flip()).asReadOnlyBuffer());

        Assert.assertEquals(1, buf.readInt());

        ByteBuffer nioBuffer = buf.nioBuffer();

        // Ensure this can be accessed without throwing a BufferUnderflowException
        Assert.assertEquals(2, nioBuffer.getInt());

        buf.release();
    }

    @Test
    public void testWrapMemoryMapped() throws Exception {
        File file = File.createTempFile("netty-test", "tmp");
        FileChannel output = null;
        FileChannel input = null;
        ByteBuf b1 = null;
        ByteBuf b2 = null;

        try {
            output = new RandomAccessFile(file, "rw").getChannel();
            byte[] bytes = new byte[1024];
            PlatformDependent.threadLocalRandom().nextBytes(bytes);
            output.write(ByteBuffer.wrap(bytes));

            input = new RandomAccessFile(file, "r").getChannel();
            ByteBuffer m = input.map(FileChannel.MapMode.READ_ONLY, 0, input.size());

            b1 = buffer(m);

            ByteBuffer dup = m.duplicate();
            dup.position(2);
            dup.limit(4);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -306,7 +306,7 @@
 
     @Test
     public void testWrapMemoryMapped() throws Exception {
-        File file = File.createTempFile("netty-test", "tmp");
+        File file = PlatformDependent.createTempFile("netty-test", "tmp", null);
         FileChannel output = null;
         FileChannel input = null;
         ByteBuf b1 = null;
```
