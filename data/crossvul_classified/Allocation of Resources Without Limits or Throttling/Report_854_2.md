# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in java
**Pair ID:** 854_2
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `854_2`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```java
Lines 162-182 of the vulnerable file.

  public abstract long readI64() throws TException;

  public abstract double readDouble() throws TException;

  public abstract float readFloat() throws TException;

  public abstract String readString() throws TException;

  public abstract byte[] readBinary() throws TException;

  /**
   * Reset any internal state back to a blank slate. This method only needs to be implemented for
   * stateful protocols.
   */
  public void reset() {}

  /** Scheme accessor */
  public Class<? extends IScheme> getScheme() {
    return StandardScheme.class;
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -179,4 +179,31 @@
   public Class<? extends IScheme> getScheme() {
     return StandardScheme.class;
   }
+
+  /** Return the minimum size of a type */
+  protected int typeMinimumSize(byte type) {
+    return 1;
+  }
+
+  protected void ensureContainerHasEnough(int size, byte type) {
+    int minimumExpected = size * typeMinimumSize(type);
+    ensureHasEnoughBytes(minimumExpected);
+  }
+
+  protected void ensureMapHasEnough(int size, byte keyType, byte valueType) {
+    int minimumExpected = size * (typeMinimumSize(keyType) + typeMinimumSize(valueType));
+    ensureHasEnoughBytes(minimumExpected);
+  }
+
+  private void ensureHasEnoughBytes(int minimumExpected) {
+    int remaining = trans_.getBytesRemainingInBuffer();
+    if (remaining < 0) {
+      return; // Some transport are not buffered
+    }
+    if (remaining < minimumExpected) {
+      throw new TProtocolException(
+          TProtocolException.INVALID_DATA,
+          "Not enough bytes to read the entire message, the data appears to be truncated");
+    }
+  }
 }
```
