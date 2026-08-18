# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 1377_3
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1377_3`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 168-208 of the vulnerable file.

      uint32_t size;
      prot.readSetBegin(elemType, size);
      skip_n(prot, size, {elemType});
      prot.readSetEnd();
      return;
    }
    case TType::T_LIST: {
      TType elemType;
      uint32_t size;
      prot.readListBegin(elemType, size);
      skip_n(prot, size, {elemType});
      prot.readListEnd();
      return;
    }
    default: {
      TProtocolException::throwInvalidSkipType(arg_type);
    }
  }
}

/*
 * Skip n tuples - used for skpping lists, sets, maps.
 *
 * As with skip(), protocols can specialize.
 */
template <class Protocol_, class WireType>
void skip_n(
    Protocol_& prot,
    uint32_t n,
    std::initializer_list<WireType> types) {
  for (uint32_t i = 0; i < n; i++) {
    for (auto type : types) {
      apache::thrift::skip(prot, type);
    }
  }
}

template <class StrType>
struct StringTraits {
  static StrType fromStringLiteral(const char* str) {
    return StrType(str);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -185,6 +185,23 @@
   }
 }
 
+/**
+ * Check if the remaining part of buffers contain least necessary amount of
+ * bytes to encode N elements of given type.
+ *
+ * Note: this is a lightweight lower bound check, it doesn't necessary mean
+ *       that we would actually succeed at reading N items.
+ */
+template <class Protocol_>
+inline bool canReadNElements(
+    Protocol_& prot,
+    uint32_t n,
+    std::initializer_list<
+        typename detail::ProtocolReaderWireTypeInfo<Protocol_>::WireType>
+        types) {
+  return prot.getCursor().canAdvance(n * types.size());
+}
+
 /*
  * Skip n tuples - used for skpping lists, sets, maps.
  *
```
