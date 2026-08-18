# CrossVul Fix Pair: Incorrect Conversion between Numeric Types in cpp
**Pair ID:** 4257_0
**Vulnerability Class:** Incorrect Conversion between Numeric Types
**CWE:** CWE-681
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4257_0`)

## Vulnerability Information & PoC

## Description
Incorrect Conversion between Numeric Types - When converting from one data type to another, such as long to integer, data can be omitted or translated in a way that produces unexpected values.

## Vulnerable Code
```cpp
Lines 3370-3411 of the vulnerable file.

        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(CreateRegExp);
        DISPATCH;
      }

      CASE(SwitchImm) {
        if (LLVM_LIKELY(O1REG(SwitchImm).isNumber())) {
          double numVal = O1REG(SwitchImm).getNumber();
          uint32_t uintVal = (uint32_t)numVal;
          if (LLVM_LIKELY(numVal == uintVal) && // Only integers.
              LLVM_LIKELY(uintVal >= ip->iSwitchImm.op4) && // Bounds checking.
              LLVM_LIKELY(uintVal <= ip->iSwitchImm.op5)) // Bounds checking.
          {
            // Calculate the offset into the bytecode where the jump table for
            // this SwitchImm starts.
            const uint8_t *tablestart = (const uint8_t *)llvh::alignAddr(
                (const uint8_t *)ip + ip->iSwitchImm.op2, sizeof(uint32_t));

            // Read the offset from the table.
            const uint32_t *loc =
                (const uint32_t *)tablestart + uintVal - ip->iSwitchImm.op4;

            ip = IPADD(*loc);
            DISPATCH;
          }
        }
        // Wrong type or out of range, jump to default.
        ip = IPADD(ip->iSwitchImm.op3);
        DISPATCH;
      }
      LOAD_CONST(
          LoadConstUInt8,
          HermesValue::encodeDoubleValue(ip->iLoadConstUInt8.op2));
      LOAD_CONST(
          LoadConstInt, HermesValue::encodeDoubleValue(ip->iLoadConstInt.op2));
      LOAD_CONST(
          LoadConstDouble,
          HermesValue::encodeDoubleValue(ip->iLoadConstDouble.op2));
      LOAD_CONST_CAPTURE_IP(
          LoadConstString,
          HermesValue::encodeStringValue(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3387,8 +3387,9 @@
                 (const uint8_t *)ip + ip->iSwitchImm.op2, sizeof(uint32_t));
 
             // Read the offset from the table.
-            const uint32_t *loc =
-                (const uint32_t *)tablestart + uintVal - ip->iSwitchImm.op4;
+            // Must be signed to account for backwards branching.
+            const int32_t *loc =
+                (const int32_t *)tablestart + uintVal - ip->iSwitchImm.op4;
 
             ip = IPADD(*loc);
             DISPATCH;
```
