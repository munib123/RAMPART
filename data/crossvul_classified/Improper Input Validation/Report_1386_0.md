# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1386_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1386_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 148-189 of the vulnerable file.

      return result;
    }
    case T_LIST: {
      uint32_t result = 0;
      TType elemType;
      uint32_t i, size;
      bool sizeUnknown;
      result += prot.readListBegin(elemType, size, sizeUnknown);
      if (!sizeUnknown) {
        for (i = 0; i < size; i++) {
          result += skip(prot, elemType);
        }
      } else {
        while (prot.peekList()) {
          result += skip(prot, elemType);
        }
      }
      result += prot.readListEnd();
      return result;
    }
    default:
      return 0;
  }
}

// TODO(denplusplus): remove.
// DO NOT USE.
template <typename Protocol_, typename T>
uint32_t readIntegral(Protocol_& prot, TType arg_type, T& value) {
  switch (arg_type) {
    case TType::T_BOOL: {
      bool boolv;
      auto res = prot.readBool(boolv);
      value = static_cast<T>(boolv);
      return res;
    }
    case TType::T_BYTE: {
      int8_t bytev;
      auto res = prot.readByte(bytev);
      value = static_cast<T>(bytev);
      return res;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,8 +165,9 @@
       result += prot.readListEnd();
       return result;
     }
-    default:
-      return 0;
+    default: {
+      TProtocolException::throwInvalidSkipType(arg_type);
+    }
   }
 }
 
```
