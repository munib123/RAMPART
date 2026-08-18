# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 1377_1
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1377_1`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 90-122 of the vulnerable file.

        case MISSING_REQUIRED_FIELD:
          return "TProtocolException: Missing required field";
        default:
          return "TProtocolException: (Invalid exception type)";
      }
    } else {
      return message_.c_str();
    }
  }

  [[noreturn]] static void throwUnionMissingStop();
  [[noreturn]] static void throwReportedTypeMismatch();
  [[noreturn]] static void throwNegativeSize();
  [[noreturn]] static void throwExceededSizeLimit();
  [[noreturn]] static void throwMissingRequiredField(
      folly::StringPiece field,
      folly::StringPiece type);
  [[noreturn]] static void throwBoolValueOutOfRange(uint8_t value);
  [[noreturn]] static void throwInvalidSkipType(TType type);
  [[noreturn]] static void throwInvalidFieldData();

 protected:
  /**
   * Error code
   */
  TProtocolExceptionType type_;
};

} // namespace protocol
} // namespace thrift
} // namespace apache

#endif // #ifndef _THRIFT_PROTOCOL_TPROTOCOLEXCEPTION_H_
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,6 +107,7 @@
   [[noreturn]] static void throwBoolValueOutOfRange(uint8_t value);
   [[noreturn]] static void throwInvalidSkipType(TType type);
   [[noreturn]] static void throwInvalidFieldData();
+  [[noreturn]] static void throwTruncatedData();
 
  protected:
   /**
```
