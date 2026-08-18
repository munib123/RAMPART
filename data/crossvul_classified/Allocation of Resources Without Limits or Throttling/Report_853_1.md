# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in java
**Pair ID:** 853_1
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `853_1`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```java
Lines 621-661 of the vulnerable file.

              trans_.getBuffer(), trans_.getBufferPosition(), length, StandardCharsets.UTF_8);
      trans_.consumeBuffer(length);
      return str;
    } else {
      return new String(readBinary(length), StandardCharsets.UTF_8);
    }
  }

  /** Read a byte[] from the wire. */
  public byte[] readBinary() throws TException {
    int length = readVarint32();
    checkReadLength(length);
    return readBinary(length);
  }

  private byte[] readBinary(int length) throws TException {
    if (length == 0) {
      return new byte[0];
    }

    byte[] buf = new byte[length];
    trans_.readAll(buf, 0, length);
    return buf;
  }

  private void checkReadLength(int length) throws TProtocolException {
    if (length < 0) {
      throw new TProtocolException("Negative length: " + length);
    }
    if (maxNetworkBytes_ != -1 && length > maxNetworkBytes_) {
      throw new TProtocolException("Length exceeded max allowed: " + length);
    }
  }

  //
  // These methods are here for the struct to call, but don't have any wire
  // encoding.
  //
  public void readMessageEnd() throws TException {}

  public void readFieldEnd() throws TException {}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -638,6 +638,7 @@
       return new byte[0];
     }
 
+    ensureContainerHasEnough(length, TType.BYTE);
     byte[] buf = new byte[length];
     trans_.readAll(buf, 0, length);
     return buf;
```
