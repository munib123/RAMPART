# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in java
**Pair ID:** 854_1
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `854_1`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```java
Lines 496-537 of the vulnerable file.

    TField field = new TField("", getTType((byte) (type & 0x0f)), fieldId);

    // if this happens to be a boolean field, the value is encoded in the type
    if (isBoolType(type)) {
      // save the boolean value in a special instance variable.
      boolValue_ = (byte) (type & 0x0f) == Types.BOOLEAN_TRUE ? Boolean.TRUE : Boolean.FALSE;
    }

    // push the new field onto the field stack so we can keep the deltas going.
    lastFieldId_ = field.id;
    return field;
  }

  /**
   * Read a map header off the wire. If the size is zero, skip reading the key and value type. This
   * means that 0-length maps will yield TMaps without the "correct" types.
   */
  public TMap readMapBegin() throws TException {
    int size = readVarint32();
    byte keyAndValueType = size == 0 ? 0 : readByte();
    return new TMap(
        getTType((byte) (keyAndValueType >> 4)), getTType((byte) (keyAndValueType & 0xf)), size);
  }

  /**
   * Read a list header off the wire. If the list size is 0-14, the size will be packed into the
   * element type header. If it's a longer list, the 4 MSB of the element type header will be 0xF,
   * and a varint will follow with the true size.
   */
  public TList readListBegin() throws TException {
    byte size_and_type = readByte();
    int size = (size_and_type >> 4) & 0x0f;
    if (size == 15) {
      size = readVarint32();
    }
    byte type = getTType(size_and_type);
    return new TList(type, size);
  }

  /**
   * Read a set header off the wire. If the set size is 0-14, the size will be packed into the
   * element type header. If it's a longer set, the 4 MSB of the element type header will be 0xF,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -513,8 +513,12 @@
   public TMap readMapBegin() throws TException {
     int size = readVarint32();
     byte keyAndValueType = size == 0 ? 0 : readByte();
-    return new TMap(
-        getTType((byte) (keyAndValueType >> 4)), getTType((byte) (keyAndValueType & 0xf)), size);
+    byte keyType = getTType((byte) (keyAndValueType >> 4));
+    byte valueType = getTType((byte) (keyAndValueType & 0xf));
+    if (size > 0) {
+      ensureMapHasEnough(size, keyType, valueType);
+    }
+    return new TMap(keyType, valueType, size);
   }
 
   /**
@@ -529,6 +533,7 @@
       size = readVarint32();
     }
     byte type = getTType(size_and_type);
+    ensureContainerHasEnough(size, type);
     return new TList(type, size);
   }
 
@@ -829,4 +834,30 @@
   private byte getCompactType(byte ttype) {
     return ttypeToCompactType[ttype];
   }
+
+  @Override
+  protected int typeMinimumSize(byte type) {
+    switch (type & 0x0f) {
+      case TType.BOOL:
+      case TType.BYTE:
+      case TType.I16: // because of variable length encoding
+      case TType.I32: // because of variable length encoding
+      case TType.I64: // because of variable length encoding
+        return 1;
+      case TType.FLOAT:
+        return 4;
+      case TType.DOUBLE:
+        return 8;
+      case TType.STRING:
+      case TType.STRUCT:
+      case TType.MAP:
+      case TType.SET:
+      case TType.LIST:
+      case TType.ENUM:
+        return 1;
+      default:
+        throw new TProtocolException(
+            TProtocolException.INVALID_DATA, "Unexpected data type " + (byte) (type & 0x0f));
+    }
+  }
 }
```
