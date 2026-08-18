# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in java
**Pair ID:** 853_0
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `853_0`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```java
Lines 326-366 of the vulnerable file.


  public float readFloat() throws TException {
    return Float.intBitsToFloat(readI32());
  }

  public String readString() throws TException {
    int size = readI32();
    checkReadLength(size);

    if (trans_.getBytesRemainingInBuffer() >= size) {
      String s =
          new String(trans_.getBuffer(), trans_.getBufferPosition(), size, StandardCharsets.UTF_8);
      trans_.consumeBuffer(size);
      return s;
    }

    return readStringBody(size);
  }

  public String readStringBody(int size) throws TException {
    checkReadLength(size);
    byte[] buf = new byte[size];
    trans_.readAll(buf, 0, size);
    return new String(buf, StandardCharsets.UTF_8);
  }

  public byte[] readBinary() throws TException {
    int size = readI32();
    checkReadLength(size);
    byte[] buf = new byte[size];
    trans_.readAll(buf, 0, size);
    return buf;
  }

  private int readAll(byte[] buf, int off, int len) throws TException {
    checkReadLength(len);
    return trans_.readAll(buf, off, len);
  }

  public void setReadLength(int readLength) {
    readLength_ = readLength;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -343,6 +343,7 @@
   }
 
   public String readStringBody(int size) throws TException {
+    ensureContainerHasEnough(size, TType.BYTE);
     checkReadLength(size);
     byte[] buf = new byte[size];
     trans_.readAll(buf, 0, size);
@@ -351,6 +352,7 @@
 
   public byte[] readBinary() throws TException {
     int size = readI32();
+    ensureContainerHasEnough(size, TType.BYTE);
     checkReadLength(size);
     byte[] buf = new byte[size];
     trans_.readAll(buf, 0, size);
```
