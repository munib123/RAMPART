# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 1377_2
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1377_2`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 365-405 of the vulnerable file.

template <>
struct ProtocolReaderStructReadState<NimbleProtocolReader>
    : NimbleProtocolReader::StructReadState {};

template <>
struct ProtocolReaderWireTypeInfo<NimbleProtocolReader> {
  using WireType = nimble::NimbleType;

  static WireType fromTType(apache::thrift::protocol::TType ttype) {
    return nimble::ttypeToNimbleType(ttype);
  }

  static WireType defaultValue() {
    return nimble::NimbleType::STOP;
  }
};

} // namespace detail

template <>
inline void skip<NimbleProtocolReader, detail::nimble::NimbleType>(
    NimbleProtocolReader& /* prot */,
    detail::nimble::NimbleType /* arg_type */) {
  // Fool the noreturn warning; we can't add the annotation without breaking
  // interface compatibility.
  volatile bool b = true;
  if (b) {
    throw std::runtime_error("Not implemented yet");
  }
}

template <>
inline void skip_n<NimbleProtocolReader, detail::nimble::NimbleType>(
    NimbleProtocolReader& prot,
    std::uint32_t n,
    std::initializer_list<detail::nimble::NimbleType> types) {
  prot.skip_n(n, types);
}

} // namespace thrift
} // namespace apache
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -382,6 +382,15 @@
 } // namespace detail
 
 template <>
+inline bool canReadNElements(
+    NimbleProtocolReader& /* prot */,
+    uint32_t /* n */,
+    std::initializer_list<detail::nimble::NimbleType> /* types */) {
+  // TODO: implement canReadNElements for NimbleProtocol
+  return true;
+}
+
+template <>
 inline void skip<NimbleProtocolReader, detail::nimble::NimbleType>(
     NimbleProtocolReader& /* prot */,
     detail::nimble::NimbleType /* arg_type */) {
```
