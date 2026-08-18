# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 1382_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1382_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 22-64 of the vulnerable file.


folly::Optional<TLSMessage> PlaintextReadRecordLayer::read(
    folly::IOBufQueue& buf) {
  while (true) {
    folly::io::Cursor cursor(buf.front());

    if (buf.empty() || !cursor.canAdvance(kPlaintextHeaderSize)) {
      return folly::none;
    }

    TLSMessage msg;
    msg.type = static_cast<ContentType>(cursor.readBE<ContentTypeType>());

    if (skipEncryptedRecords_) {
      if (msg.type == ContentType::application_data) {
        cursor.skip(sizeof(ProtocolVersion));
        auto length = cursor.readBE<uint16_t>();
        if (buf.chainLength() < (cursor - buf.front()) + length) {
          return folly::none;
        }
        length +=
            sizeof(ContentType) + sizeof(ProtocolVersion) + sizeof(uint16_t);
        buf.trimStart(length);
        continue;
      } else if (msg.type != ContentType::change_cipher_spec) {
        skipEncryptedRecords_ = false;
      }
    }

    switch (msg.type) {
      case ContentType::handshake:
      case ContentType::alert:
        break;
      case ContentType::change_cipher_spec:
        break;
      default:
        throw std::runtime_error(folly::to<std::string>(
            "received plaintext content type ",
            static_cast<ContentTypeType>(msg.type),
            ", header: ",
            folly::hexlify(buf.splitAtMost(10)->coalesce())));
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,9 +39,7 @@
         if (buf.chainLength() < (cursor - buf.front()) + length) {
           return folly::none;
         }
-        length +=
-            sizeof(ContentType) + sizeof(ProtocolVersion) + sizeof(uint16_t);
-        buf.trimStart(length);
+        buf.trimStart(static_cast<size_t>(kPlaintextHeaderSize) + length);
         continue;
       } else if (msg.type != ContentType::change_cipher_spec) {
         skipEncryptedRecords_ = false;
```
