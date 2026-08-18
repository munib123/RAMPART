# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 1378_0
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1378_0`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 536-576 of the vulnerable file.

  readI32(size);
  checkStringSize(size);

  in_.clone(str, size);
  if (sharing_ != SHARE_EXTERNAL_BUFFER) {
    str.makeManaged();
  }
}

template <typename StrType>
void BinaryProtocolReader::readStringBody(StrType& str, int32_t size) {
  checkStringSize(size);

  // Catch empty string case
  if (size == 0) {
    str.clear();
    return;
  }

  if (static_cast<int32_t>(in_.length()) < size) {
    str.reserve(size); // only reserve for multi iter case below
  }
  str.clear();
  size_t size_left = size;
  while (size_left > 0) {
    auto data = in_.peekBytes();
    auto data_avail = std::min(data.size(), size_left);
    if (data.empty()) {
      TProtocolException::throwExceededSizeLimit();
    }

    str.append((const char*)data.data(), data_avail);
    size_left -= data_avail;
    in_.skipNoAdvance(data_avail);
  }
}

uint32_t BinaryProtocolReader::readFromPositionAndAppend(
    Cursor& snapshot,
    std::unique_ptr<IOBuf>& ser) {
  int32_t size = folly::io::Cursor(in_) - snapshot;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -553,6 +553,9 @@
   }
 
   if (static_cast<int32_t>(in_.length()) < size) {
+    if (!in_.canAdvance(size)) {
+      protocol::TProtocolException::throwTruncatedData();
+    }
     str.reserve(size); // only reserve for multi iter case below
   }
   str.clear();
```
