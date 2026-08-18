# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 1029_7
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1029_7`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 492-532 of the vulnerable file.

      return NGHTTP2_ERR_FLOODED;
    }
  }

  // Only raise GOAWAY once, since we don't currently expose stream information. Shutdown
  // notifications are the same as a normal GOAWAY.
  if (frame->hd.type == NGHTTP2_GOAWAY && !raised_goaway_) {
    ASSERT(frame->hd.stream_id == 0);
    raised_goaway_ = true;
    callbacks().onGoAway();
    return 0;
  }

  StreamImpl* stream = getStream(frame->hd.stream_id);
  if (!stream) {
    return 0;
  }

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS: {
    stream->remote_end_stream_ = frame->hd.flags & NGHTTP2_FLAG_END_STREAM;
    if (!stream->cookies_.empty()) {
      HeaderString key(Headers::get().Cookie);
      stream->headers_->addViaMove(std::move(key), std::move(stream->cookies_));
    }

    switch (frame->headers.cat) {
    case NGHTTP2_HCAT_RESPONSE: {
      if (CodeUtility::is1xx(Http::Utility::getResponseStatus(*stream->headers_))) {
        stream->waiting_for_non_informational_headers_ = true;
      }

      if (stream->headers_->Status()->value() == "100") {
        ASSERT(!stream->remote_end_stream_);
        stream->decoder_->decode100ContinueHeaders(std::move(stream->headers_));
      } else {
        stream->decodeHeaders();
      }
      break;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -509,6 +509,10 @@
 
   switch (frame->hd.type) {
   case NGHTTP2_HEADERS: {
+    // Verify that the final HeaderMap's byte size is under the limit before decoding headers.
+    // This assert iterates over the HeaderMap.
+    ASSERT(stream->headers_->byteSize().has_value() &&
+           stream->headers_->byteSize().value() == stream->headers_->byteSizeInternal());
     stream->remote_end_stream_ = frame->hd.flags & NGHTTP2_FLAG_END_STREAM;
     if (!stream->cookies_.empty()) {
       HeaderString key(Headers::get().Cookie);
@@ -620,6 +624,12 @@
   case NGHTTP2_HEADERS:
   case NGHTTP2_DATA: {
     StreamImpl* stream = getStream(frame->hd.stream_id);
+    if (stream->headers_) {
+      // Verify that the final HeaderMap's byte size is under the limit before sending frames.
+      // This assert iterates over the HeaderMap.
+      ASSERT(stream->headers_->byteSize().has_value() &&
+             stream->headers_->byteSize().value() == stream->headers_->byteSizeInternal());
+    }
     stream->local_end_stream_sent_ = frame->hd.flags & NGHTTP2_FLAG_END_STREAM;
     break;
   }
@@ -808,9 +818,10 @@
     stats_.headers_cb_no_stream_.inc();
     return 0;
   }
-
   stream->saveHeader(std::move(name), std::move(value));
-  if (stream->headers_->byteSize() > max_request_headers_kb_ * 1024) {
+  // Verify that the cached value in byte size exists.
+  ASSERT(stream->headers_->byteSize().has_value());
+  if (stream->headers_->byteSize().value() > max_request_headers_kb_ * 1024) {
     // This will cause the library to reset/close the stream.
     stats_.header_overflow_.inc();
     return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
```
