# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 842_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `842_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 96-136 of the vulnerable file.

        return decryptAttempt;
      } else {
        continue;
      }
    } else {
      return aead_->decrypt(
          std::move(encrypted),
          useAdditionalData_ ? &adBuf : nullptr,
          seqNum_++);
    }
  }
}

folly::Optional<TLSMessage> EncryptedReadRecordLayer::read(
    folly::IOBufQueue& buf) {
  auto decryptedBuf = getDecryptedBuf(buf);
  if (!decryptedBuf) {
    return folly::none;
  }

  TLSMessage msg;
  // Iterate over the buffers while trying to find
  // the first non-zero octet. This is much faster than
  // first iterating and then trimming.
  auto currentBuf = decryptedBuf->get();
  bool nonZeroFound = false;
  do {
    currentBuf = currentBuf->prev();
    size_t i = currentBuf->length();
    while (i > 0 && !nonZeroFound) {
      nonZeroFound = (currentBuf->data()[i - 1] != 0);
      i--;
    }
    if (nonZeroFound) {
      msg.type = static_cast<ContentType>(currentBuf->data()[i]);
    }
    currentBuf->trimEnd(currentBuf->length() - i);
  } while (!nonZeroFound && currentBuf != decryptedBuf->get());
  if (!nonZeroFound) {
    throw std::runtime_error("No content type found");
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,7 +113,7 @@
     return folly::none;
   }
 
-  TLSMessage msg;
+  TLSMessage msg{};
   // Iterate over the buffers while trying to find
   // the first non-zero octet. This is much faster than
   // first iterating and then trimming.
```
