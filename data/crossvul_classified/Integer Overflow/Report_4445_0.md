# CrossVul Fix Pair: Integer Overflow or Wraparound in java
**Pair ID:** 4445_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4445_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```java
Lines 35-68 of the vulnerable file.

  }

  private static native int open(String path, boolean append) throws IOException;

  private static native void write(int fd, int c) throws IOException;

  private static native void write(int fd, byte[] b, int offset, int length)
    throws IOException;

  private static native void close(int fd) throws IOException;

  public void write(int c) throws IOException {
    write(fd, c);
  }

  public void write(byte[] b, int offset, int length) throws IOException {
    if (b == null) {
      throw new NullPointerException();
    }

    if (offset < 0 || offset + length > b.length) {
      throw new ArrayIndexOutOfBoundsException();
    }

    write(fd, b, offset, length);
  }

  public void close() throws IOException {
    if (fd != -1) {
      close(fd);
      fd = -1;
    }
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,7 @@
       throw new NullPointerException();
     }
 
-    if (offset < 0 || offset + length > b.length) {
+    if (offset < 0 || length < 0 || length > b.length || offset > b.length - length) {
       throw new ArrayIndexOutOfBoundsException();
     }
 
```
