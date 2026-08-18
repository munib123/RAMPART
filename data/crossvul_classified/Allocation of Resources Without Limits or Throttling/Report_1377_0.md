# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in cpp
**Pair ID:** 1377_0
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1377_0`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```cpp
Lines 58-80 of the vulnerable file.

      TProtocolException::INVALID_DATA,
      fmt::format(
          "Attempt to interpret value {} as bool, probably the data is "
          "corrupted",
          value));
}

[[noreturn]] void TProtocolException::throwInvalidSkipType(TType type) {
  throw TProtocolException(
      TProtocolException::INVALID_DATA,
      fmt::format(
          "Encountered invalid field/element type ({}) during skipping",
          static_cast<uint8_t>(type)));
}

[[noreturn]] void TProtocolException::throwInvalidFieldData() {
  throw TProtocolException(
      TProtocolException::INVALID_DATA,
      "The field stream contains corrupted data");
}
} // namespace protocol
} // namespace thrift
} // namespace apache
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,6 +75,13 @@
       TProtocolException::INVALID_DATA,
       "The field stream contains corrupted data");
 }
+
+[[noreturn]] void TProtocolException::throwTruncatedData() {
+  throw TProtocolException(
+      TProtocolException::INVALID_DATA,
+      "Not enough bytes to read the entire message, the data appears to be "
+      "truncated");
+}
 } // namespace protocol
 } // namespace thrift
 } // namespace apache
```
