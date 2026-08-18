# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1376_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1376_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 40-60 of the vulnerable file.

  throw TProtocolException(TProtocolException::SIZE_LIMIT);
}

[[noreturn]] void TProtocolException::throwMissingRequiredField(
    folly::StringPiece field,
    folly::StringPiece type) {
  constexpr auto fmt =
      "Required field '{}' was not found in serialized data! Struct: {}";
  throw TProtocolException(
      TProtocolException::MISSING_REQUIRED_FIELD,
      folly::sformat(fmt, field, type));
}

[[noreturn]] void TProtocolException::throwBoolValueOutOfRange(uint8_t value) {
  throw TProtocolException(
      TProtocolException::INVALID_DATA,
      folly::sformat(
          "Attempt to interpret value {} as bool, probably the data is corrupted",
          value));
}
}}}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,4 +57,12 @@
           "Attempt to interpret value {} as bool, probably the data is corrupted",
           value));
 }
+
+[[noreturn]] void TProtocolException::throwInvalidSkipType(TType type) {
+  throw TProtocolException(
+      TProtocolException::INVALID_DATA,
+      folly::sformat(
+          "Encountered invalid field/element type ({}) during skipping",
+          static_cast<uint8_t>(type)));
+}
 }}}
```
