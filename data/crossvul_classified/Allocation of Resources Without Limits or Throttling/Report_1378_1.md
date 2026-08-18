# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 1378_1
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1378_1`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 655-695 of the vulnerable file.


  uint32_t bits = in_.readBE<int32_t>();
  flt = bitwise_cast<float>(bits);
}

void CompactProtocolReader::readStringSize(int32_t& size) {
  apache::thrift::util::readVarint(in_, size);

  // Catch error cases
  if (size < 0) {
    TProtocolException::throwNegativeSize();
  }
  if (string_limit_ > 0 && size > string_limit_) {
    TProtocolException::throwExceededSizeLimit();
  }
}

template <typename StrType>
void CompactProtocolReader::readStringBody(StrType& str, int32_t size) {
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

template <typename StrType>
void CompactProtocolReader::readString(StrType& str) {
  int32_t size = 0;
  readStringSize(size);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -672,6 +672,9 @@
 template <typename StrType>
 void CompactProtocolReader::readStringBody(StrType& str, int32_t size) {
   if (static_cast<int32_t>(in_.length()) < size) {
+    if (!in_.canAdvance(size)) {
+      protocol::TProtocolException::throwTruncatedData();
+    }
     str.reserve(size); // only reserve for multi iter case below
   }
   str.clear();
```
