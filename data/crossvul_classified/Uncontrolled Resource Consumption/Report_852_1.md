# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 852_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `852_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 228-269 of the vulnerable file.

    static_assert(
        sizeof(Result) == sizeof(carbon::Result),
        "Carbon currently assumes sizeof(Result) == sizeof(int16_t)");
    r = static_cast<Result>(readRaw<int16_t>());
  }

  void readRawInto(std::string& s) {
    s = cursor_.readFixedString(readVarint<uint32_t>());
  }

  void readRawInto(folly::IOBuf& buf) {
    cursor_.clone(buf, readVarint<uint32_t>());
  }

  void readStructBegin() {
    nestedStructFieldIds_.push_back(lastFieldId_);
    lastFieldId_ = 0;
  }

  void readStructEnd() {
    lastFieldId_ = nestedStructFieldIds_.back();
    nestedStructFieldIds_.pop_back();
  }

  std::pair<std::pair<FieldType, FieldType>, uint32_t>
  readKVContainerFieldSizeAndInnerTypes() {
    std::pair<std::pair<FieldType, FieldType>, uint32_t> pr;
    const auto len = readVarint<uint32_t>();
    pr.second = len;
    uint8_t byte = 0;
    if (len > 0) {
      byte = readByte();
    }
    pr.first.first = static_cast<FieldType>((byte & 0xf0) >> 4); // key-type
    pr.first.second = static_cast<FieldType>(byte & 0x0f); // value-type
    return pr;
  }

  std::pair<FieldType, uint32_t> readLinearContainerFieldSizeAndInnerType() {
    std::pair<FieldType, uint32_t> pr;
    const uint8_t byte = readByte();
    pr.first = static_cast<FieldType>(byte & 0x0f);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -245,8 +245,10 @@
   }
 
   void readStructEnd() {
-    lastFieldId_ = nestedStructFieldIds_.back();
-    nestedStructFieldIds_.pop_back();
+    if (!nestedStructFieldIds_.empty()) {
+      lastFieldId_ = nestedStructFieldIds_.back();
+      nestedStructFieldIds_.pop_back();
+    }
   }
 
   std::pair<std::pair<FieldType, FieldType>, uint32_t>
```
