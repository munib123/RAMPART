# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 843_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `843_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 130-170 of the vulnerable file.

      msg.type = static_cast<ContentType>(currentBuf->data()[i]);
    }
    currentBuf->trimEnd(currentBuf->length() - i);
  } while (!nonZeroFound && currentBuf != decryptedBuf->get());
  if (!nonZeroFound) {
    throw std::runtime_error("No content type found");
  }
  msg.fragment = std::move(*decryptedBuf);

  switch (msg.type) {
    case ContentType::handshake:
    case ContentType::alert:
    case ContentType::application_data:
      break;
    default:
      throw std::runtime_error(folly::to<std::string>(
          "received encrypted content type ",
          static_cast<ContentTypeType>(msg.type)));
  }

  if (!msg.fragment) {
    if (msg.type == ContentType::application_data) {
      msg.fragment = folly::IOBuf::create(0);
    } else {
      throw std::runtime_error("received empty fragment");
    }
  }

  return msg;
}

EncryptionLevel EncryptedReadRecordLayer::getEncryptionLevel() const {
  return encryptionLevel_;
}

EncryptedWriteRecordLayer::EncryptedWriteRecordLayer(
    EncryptionLevel encryptionLevel)
    : encryptionLevel_(encryptionLevel) {}

TLSContent EncryptedWriteRecordLayer::write(TLSMessage&& msg) const {
  folly::IOBufQueue queue;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -147,7 +147,7 @@
           static_cast<ContentTypeType>(msg.type)));
   }
 
-  if (!msg.fragment) {
+  if (!msg.fragment || msg.fragment->empty()) {
     if (msg.type == ContentType::application_data) {
       msg.fragment = folly::IOBuf::create(0);
     } else {
```
