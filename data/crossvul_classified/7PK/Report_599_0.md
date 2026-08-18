# CrossVul Fix Pair: 7PK in cpp
**Pair ID:** 599_0
**Vulnerability Class:** 7PK
**CWE:** CWE-388
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `599_0`)

## Vulnerability Information & PoC

## Description
7PK - Errors

## Vulnerable Code
```cpp
Lines 497-537 of the vulnerable file.

  }
  return ErrorCode::NO_ERROR;
}

folly::Optional<ErrorCode> HTTP2Codec::parseHeadersDecodeFrames(
    const folly::Optional<http2::PriorityUpdate>& priority,
    const folly::Optional<uint32_t>& promisedStream,
    const folly::Optional<ExAttributes>& exAttributes,
    std::unique_ptr<HTTPMessage>& msg) {
  // decompress headers
  Cursor headerCursor(curHeaderBlock_.front());
  bool isReq = false;
  if (promisedStream) {
    isReq = true;
  } else if (exAttributes) {
    isReq = isRequest(curHeader_.stream);
  } else {
    isReq = transportDirection_ == TransportDirection::DOWNSTREAM;
  }

  decodeInfo_.init(isReq, parsingDownstreamTrailers_);
  if (priority) {
    if (curHeader_.stream == priority->streamDependency) {
      streamError(folly::to<string>("Circular dependency for txn=",
                                    curHeader_.stream),
                  ErrorCode::PROTOCOL_ERROR,
                  curHeader_.type == http2::FrameType::HEADERS);
      return ErrorCode::NO_ERROR;
    }

    decodeInfo_.msg->setHTTP2Priority(
        std::make_tuple(priority->streamDependency,
                        priority->exclusive,
                        priority->weight));
  }
  headerCodec_.decodeStreaming(
      headerCursor, curHeaderBlock_.chainLength(), this);
  msg = std::move(decodeInfo_.msg);
  // Saving this in case we need to log it on error
  auto g = folly::makeGuard([this] { curHeaderBlock_.move(); });
  // Check decoding error
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -514,21 +514,23 @@
     isReq = transportDirection_ == TransportDirection::DOWNSTREAM;
   }
 
+  // Validate circular dependencies.
+  if (priority && (curHeader_.stream == priority->streamDependency)) {
+    streamError(
+        folly::to<string>("Circular dependency for txn=", curHeader_.stream),
+        ErrorCode::PROTOCOL_ERROR,
+        curHeader_.type == http2::FrameType::HEADERS);
+    return ErrorCode::NO_ERROR;
+  }
+
   decodeInfo_.init(isReq, parsingDownstreamTrailers_);
   if (priority) {
-    if (curHeader_.stream == priority->streamDependency) {
-      streamError(folly::to<string>("Circular dependency for txn=",
-                                    curHeader_.stream),
-                  ErrorCode::PROTOCOL_ERROR,
-                  curHeader_.type == http2::FrameType::HEADERS);
-      return ErrorCode::NO_ERROR;
-    }
-
     decodeInfo_.msg->setHTTP2Priority(
         std::make_tuple(priority->streamDependency,
                         priority->exclusive,
                         priority->weight));
   }
+
   headerCodec_.decodeStreaming(
       headerCursor, curHeaderBlock_.chainLength(), this);
   msg = std::move(decodeInfo_.msg);
```
