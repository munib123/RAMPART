# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1376_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1376_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 159-200 of the vulnerable file.

    case TType::T_SET: {
      TType elemType;
      uint32_t i, size;
      prot.readSetBegin(elemType, size);
      for (i = 0; i < size; i++) {
        apache::thrift::skip(prot, elemType);
      }
      prot.readSetEnd();
      return;
    }
    case TType::T_LIST: {
      TType elemType;
      uint32_t i, size;
      prot.readListBegin(elemType, size);
      for (i = 0; i < size; i++) {
        apache::thrift::skip(prot, elemType);
      }
      prot.readListEnd();
      return;
    }
    default:
      return;
  }
}

template <class StrType>
struct StringTraits {
  static StrType fromStringLiteral(const char* str) {
    return StrType(str);
  }

  static bool isEmpty(const StrType& str) {
    return str.empty();
  }

  static bool isEqual(const StrType& lhs, const StrType& rhs) {
    return lhs == rhs;
  }

  static bool isLess(const StrType& lhs, const StrType& rhs) {
    return lhs < rhs;
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,8 +176,9 @@
       prot.readListEnd();
       return;
     }
-    default:
-      return;
+    default: {
+      TProtocolException::throwInvalidSkipType(arg_type);
+    }
   }
 }
 
```
