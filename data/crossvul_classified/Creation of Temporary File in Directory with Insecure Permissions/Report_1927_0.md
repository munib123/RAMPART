# CrossVul Fix Pair: Creation of Temporary File in Directory with Insecure Permissions in java
**Pair ID:** 1927_0
**Vulnerability Class:** Creation of Temporary File in Directory with Insecure Permissions
**CWE:** CWE-379
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1927_0`)

## Vulnerability Information & PoC

## Description
Creation of Temporary File in Directory with Insecure Permissions - On some operating systems, the fact that the temporary file exists may be apparent to any user with sufficient privileges to access that directory.

## Vulnerable Code
```java
Lines 4534-4574 of the vulnerable file.

    private void testGetReadOnlyDst(boolean direct) {
        byte[] bytes = { 'a', 'b', 'c', 'd' };

        ByteBuf buffer = newBuffer(bytes.length);
        buffer.writeBytes(bytes);

        ByteBuffer dst = direct ? ByteBuffer.allocateDirect(bytes.length) : ByteBuffer.allocate(bytes.length);
        ByteBuffer readOnlyDst = dst.asReadOnlyBuffer();
        try {
            buffer.getBytes(0, readOnlyDst);
            fail();
        } catch (ReadOnlyBufferException e) {
            // expected
        }
        assertEquals(0, readOnlyDst.position());
        buffer.release();
    }

    @Test
    public void testReadBytesAndWriteBytesWithFileChannel() throws IOException {
        File file = File.createTempFile("file-channel", ".tmp");
        RandomAccessFile randomAccessFile = null;
        try {
            randomAccessFile = new RandomAccessFile(file, "rw");
            FileChannel channel = randomAccessFile.getChannel();
            // channelPosition should never be changed
            long channelPosition = channel.position();

            byte[] bytes = {'a', 'b', 'c', 'd'};
            int len = bytes.length;
            ByteBuf buffer = newBuffer(len);
            buffer.resetReaderIndex();
            buffer.resetWriterIndex();
            buffer.writeBytes(bytes);

            int oldReaderIndex = buffer.readerIndex();
            assertEquals(len, buffer.readBytes(channel, 10, len));
            assertEquals(oldReaderIndex + len, buffer.readerIndex());
            assertEquals(channelPosition, channel.position());

            ByteBuf buffer2 = newBuffer(len);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4551,7 +4551,7 @@
 
     @Test
     public void testReadBytesAndWriteBytesWithFileChannel() throws IOException {
-        File file = File.createTempFile("file-channel", ".tmp");
+        File file = PlatformDependent.createTempFile("file-channel", ".tmp", null);
         RandomAccessFile randomAccessFile = null;
         try {
             randomAccessFile = new RandomAccessFile(file, "rw");
@@ -4594,7 +4594,7 @@
 
     @Test
     public void testGetBytesAndSetBytesWithFileChannel() throws IOException {
-        File file = File.createTempFile("file-channel", ".tmp");
+        File file = PlatformDependent.createTempFile("file-channel", ".tmp", null);
         RandomAccessFile randomAccessFile = null;
         try {
             randomAccessFile = new RandomAccessFile(file, "rw");
```
