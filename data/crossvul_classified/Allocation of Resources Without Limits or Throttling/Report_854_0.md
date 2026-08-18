# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in java
**Pair ID:** 854_0
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `854_0`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```java
Lines 208-248 of the vulnerable file.

  }

  public void readMessageEnd() {}

  public TStruct readStructBegin(
      Map<Integer, com.facebook.thrift.meta_data.FieldMetaData> metaDataMap) {
    return ANONYMOUS_STRUCT;
  }

  public void readStructEnd() {}

  public TField readFieldBegin() throws TException {
    byte type = readByte();
    short id = type == TType.STOP ? 0 : readI16();
    return new TField("", type, id);
  }

  public void readFieldEnd() {}

  public TMap readMapBegin() throws TException {
    return new TMap(readByte(), readByte(), readI32());
  }

  public void readMapEnd() {}

  public TList readListBegin() throws TException {
    return new TList(readByte(), readI32());
  }

  public void readListEnd() {}

  public TSet readSetBegin() throws TException {
    return new TSet(readByte(), readI32());
  }

  public void readSetEnd() {}

  public boolean readBool() throws TException {
    return (readByte() == 1);
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -225,19 +225,29 @@
   public void readFieldEnd() {}
 
   public TMap readMapBegin() throws TException {
-    return new TMap(readByte(), readByte(), readI32());
+    byte keyType = readByte();
+    byte valueType = readByte();
+    int size = readI32();
+    ensureMapHasEnough(size, keyType, valueType);
+    return new TMap(keyType, valueType, size);
   }
 
   public void readMapEnd() {}
 
   public TList readListBegin() throws TException {
-    return new TList(readByte(), readI32());
+    byte type = readByte();
+    int size = readI32();
+    ensureContainerHasEnough(size, type);
+    return new TList(type, size);
   }
 
   public void readListEnd() {}
 
   public TSet readSetBegin() throws TException {
-    return new TSet(readByte(), readI32());
+    byte type = readByte();
+    int size = readI32();
+    ensureContainerHasEnough(size, type);
+    return new TSet(type, size);
   }
 
   public void readSetEnd() {}
@@ -368,4 +378,35 @@
       }
     }
   }
+
+  @Override
+  protected int typeMinimumSize(byte type) {
+    switch (type & 0x0f) {
+      case TType.BOOL:
+      case TType.BYTE:
+        return 1;
+      case TType.I16:
+        return 2;
+      case TType.I32:
+      case TType.FLOAT:
+        return 4;
+      case TType.DOUBLE:
+      case TType.I64:
+        return 8;
+      case TType.STRING:
+        return 4;
+      case TType.LIST:
+      case TType.SET:
+        // type (1 byte) + size (4 bytes)
+        return 1 + 4;
+      case TType.MAP:
+        // key type (1 byte) + value type (1 byte) + size (4 bytes)
+        return 1 + 1 + 4;
+      case TType.STRUCT:
+        return 1;
+      default:
+        throw new TProtocolException(
+            TProtocolException.INVALID_DATA, "Unexpected data type " + (byte) (type & 0x0f));
+    }
+  }
 }
```
