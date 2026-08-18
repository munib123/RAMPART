# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 1376_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1376_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 160-202 of the vulnerable file.


    def readI16(self):
        pass

    def readI32(self):
        pass

    def readI64(self):
        pass

    def readDouble(self):
        pass

    def readFloat(self):
        pass

    def readString(self):
        pass

    def skip(self, type):
        if type == TType.STOP:
            return
        elif type == TType.BOOL:
            self.readBool()
        elif type == TType.BYTE:
            self.readByte()
        elif type == TType.I16:
            self.readI16()
        elif type == TType.I32:
            self.readI32()
        elif type == TType.I64:
            self.readI64()
        elif type == TType.DOUBLE:
            self.readDouble()
        elif type == TType.FLOAT:
            self.readFloat()
        elif type == TType.STRING:
            self.readString()
        elif type == TType.STRUCT:
            name = self.readStructBegin()
            while True:
                (name, type, id) = self.readFieldBegin()
                if type == TType.STOP:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -177,9 +177,7 @@
         pass
 
     def skip(self, type):
-        if type == TType.STOP:
-            return
-        elif type == TType.BOOL:
+        if type == TType.BOOL:
             self.readBool()
         elif type == TType.BYTE:
             self.readByte()
@@ -220,6 +218,11 @@
             for _ in range(size):
                 self.skip(etype)
             self.readListEnd()
+        else:
+            raise TProtocolException(
+                TProtocolException.INVALID_DATA,
+                "Unexpected type for skipping {}".format(type)
+            )
 
     def readIntegral(self, type):
         if type == TType.BOOL:
```
