# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in java
**Pair ID:** 854_3
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `854_3`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```java
Lines 200-220 of the vulnerable file.


  public long readI64() throws TException {
    return concreteProtocol.readI64();
  }

  public float readFloat() throws TException {
    return concreteProtocol.readFloat();
  }

  public double readDouble() throws TException {
    return concreteProtocol.readDouble();
  }

  public String readString() throws TException {
    return concreteProtocol.readString();
  }

  public byte[] readBinary() throws TException {
    return concreteProtocol.readBinary();
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -217,4 +217,9 @@
   public byte[] readBinary() throws TException {
     return concreteProtocol.readBinary();
   }
+
+  @Override
+  protected int typeMinimumSize(byte type) {
+    return concreteProtocol.typeMinimumSize(type);
+  }
 }
```
