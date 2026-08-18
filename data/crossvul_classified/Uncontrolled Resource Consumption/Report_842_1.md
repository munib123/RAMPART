# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 842_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `842_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 32-72 of the vulnerable file.

    auto message = read(socketBuf);
    if (!message) {
      return folly::none;
    }

    if (!unparsedHandshakeData_.empty() &&
        message->type != ContentType::handshake) {
      throw std::runtime_error("spliced handshake data");
    }

    switch (message->type) {
      case ContentType::alert: {
        auto alert = decode<Alert>(std::move(message->fragment));
        if (alert.description == AlertDescription::close_notify) {
          return Param(CloseNotify(socketBuf.move()));
        } else {
          return Param(std::move(alert));
        }
      }
      case ContentType::handshake: {
        unparsedHandshakeData_.append(std::move(message->fragment));
        auto param = decodeHandshakeMessage(unparsedHandshakeData_);
        if (param) {
          VLOG(8) << "Received handshake message "
                  << toString(boost::apply_visitor(EventVisitor(), *param));
          return param;
        } else {
          // If we read handshake data but didn't have enough to get a full
          // message we immediately try to read another record.
          // TODO: add limits on number of records we buffer
          continue;
        }
      }
      case ContentType::application_data:
        return Param(AppData(std::move(message->fragment)));
      default:
        throw std::runtime_error("unknown content type");
    }
  }
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,7 +49,31 @@
         }
       }
       case ContentType::handshake: {
-        unparsedHandshakeData_.append(std::move(message->fragment));
+        std::unique_ptr<folly::IOBuf> handshakeMessage =
+            unparsedHandshakeData_.move();
+        // It is possible that a peer might send us records in a manner such
+        // that there is a 16KB record and only 1 byte of handshake message in
+        // each record. Since we normally just trim the IOBuf, we would end up
+        // holding 16K of data. To prevent this we allocate a contiguous
+        // buffer to copy over these bytes. We supply kExtraAlloc bytes in
+        // order to avoid needing to re-allocate a lot of times if we receive
+        // a lot of small messages. There might be more optimal reallocation
+        // policies, but this should be fine.
+        message->fragment->coalesce();
+        constexpr size_t kExtraAlloc = 1024;
+        if (!handshakeMessage) {
+          handshakeMessage =
+              folly::IOBuf::create(message->fragment->length() + kExtraAlloc);
+        } else if (handshakeMessage->tailroom() < message->fragment->length()) {
+          handshakeMessage->reserve(
+              0, message->fragment->length() + kExtraAlloc);
+        }
+        memcpy(
+            handshakeMessage->writableTail(),
+            message->fragment->data(),
+            message->fragment->length());
+        handshakeMessage->append(message->fragment->length());
+        unparsedHandshakeData_.append(std::move(handshakeMessage));
         auto param = decodeHandshakeMessage(unparsedHandshakeData_);
         if (param) {
           VLOG(8) << "Received handshake message "
```
