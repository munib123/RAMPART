# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 1377_4
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1377_4`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 515-555 of the vulnerable file.

  template <typename Protocol>
  static void read(Protocol& protocol, Type& out) {
    std::uint32_t list_size = -1;
    using WireTypeInfo = ProtocolReaderWireTypeInfo<Protocol>;
    using WireType = typename WireTypeInfo::WireType;

    WireType reported_type = WireTypeInfo::defaultValue();

    protocol.readListBegin(reported_type, list_size);
    if (protocol.kOmitsContainerSizes()) {
      // list size unknown, SimpleJSON protocol won't know type, either
      // so let's just hope that it spits out something that makes sense
      while (protocol.peekList()) {
        out.emplace_back();
        elem_methods::read(protocol, out.back());
      }
    } else {
      if (reported_type != WireTypeInfo::fromTType(elem_methods::ttype_value)) {
        apache::thrift::skip_n(protocol, list_size, {reported_type});
      } else {
        using traits = std::iterator_traits<typename Type::iterator>;
        using cat = typename traits::iterator_category;
        if (reserve_if_possible(&out, list_size) ||
            std::is_same<cat, std::bidirectional_iterator_tag>::value) {
          // use bidi as a hint for doubly linked list containers like std::list
          while (list_size--) {
            out.emplace_back();
            elem_methods::read(protocol, out.back());
          }
        } else {
          out.resize(list_size);
          for (auto&& elem : out) {
            elem_methods::read(protocol, elem);
          }
        }
      }
    }
    protocol.readListEnd();
  }

  template <typename Protocol>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -532,6 +532,10 @@
       if (reported_type != WireTypeInfo::fromTType(elem_methods::ttype_value)) {
         apache::thrift::skip_n(protocol, list_size, {reported_type});
       } else {
+        if (!canReadNElements(protocol, list_size, {reported_type})) {
+          protocol::TProtocolException::throwTruncatedData();
+        }
+
         using traits = std::iterator_traits<typename Type::iterator>;
         using cat = typename traits::iterator_category;
         if (reserve_if_possible(&out, list_size) ||
@@ -619,6 +623,9 @@
       if (reported_type != WireTypeInfo::fromTType(elem_methods::ttype_value)) {
         apache::thrift::skip_n(protocol, set_size, {reported_type});
       } else {
+        if (!canReadNElements(protocol, set_size, {reported_type})) {
+          protocol::TProtocolException::throwTruncatedData();
+        }
         auto const vreader = [&protocol](auto& value) {
           elem_methods::read(protocol, value);
         };
@@ -722,6 +729,10 @@
         apache::thrift::skip_n(
             protocol, map_size, {rpt_key_type, rpt_mapped_type});
       } else {
+        if (!canReadNElements(
+                protocol, map_size, {rpt_key_type, rpt_mapped_type})) {
+          protocol::TProtocolException::throwTruncatedData();
+        }
         auto const kreader = [&protocol](auto& key) {
           key_methods::read(protocol, key);
         };
```
