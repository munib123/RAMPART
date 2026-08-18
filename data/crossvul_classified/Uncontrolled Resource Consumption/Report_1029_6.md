# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 1029_6
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1029_6`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 443-484 of the vulnerable file.

  const absl::string_view header_value = absl::string_view(data, length);

  if (strict_header_validation_) {
    if (!Http::HeaderUtility::headerIsValid(header_value)) {
      ENVOY_CONN_LOG(debug, "invalid header value: {}", connection_, header_value);
      error_code_ = Http::Code::BadRequest;
      sendProtocolError();
      throw CodecProtocolException("http/1.1 protocol error: header value contains invalid chars");
    }
  } else if (header_value.find('\0') != absl::string_view::npos) {
    // http-parser should filter for this
    // (https://tools.ietf.org/html/rfc7230#section-3.2.6), but it doesn't today. HeaderStrings
    // have an invariant that they must not contain embedded zero characters
    // (NUL, ASCII 0x0).
    throw CodecProtocolException("http/1.1 protocol error: header value contains NUL");
  }

  header_parsing_state_ = HeaderParsingState::Value;
  current_header_value_.append(data, length);

  const uint32_t total =
      current_header_field_.size() + current_header_value_.size() + current_header_map_->byteSize();
  if (total > (max_request_headers_kb_ * 1024)) {
    error_code_ = Http::Code::RequestHeaderFieldsTooLarge;
    sendProtocolError();
    throw CodecProtocolException("headers size exceeds limit");
  }
}

int ConnectionImpl::onHeadersCompleteBase() {
  ENVOY_CONN_LOG(trace, "headers complete", connection_);
  completeLastHeader();
  if (!(parser_.http_major == 1 && parser_.http_minor == 1)) {
    // This is not necessarily true, but it's good enough since higher layers only care if this is
    // HTTP/1.1 or not.
    protocol_ = Protocol::Http10;
  }
  if (Utility::isUpgrade(*current_header_map_)) {
    // Ignore h2c upgrade requests until we support them.
    // See https://github.com/envoyproxy/envoy/issues/7161 for details.
    if (current_header_map_->Upgrade() &&
        absl::EqualsIgnoreCase(current_header_map_->Upgrade()->value().getStringView(),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -460,8 +460,10 @@
   header_parsing_state_ = HeaderParsingState::Value;
   current_header_value_.append(data, length);
 
-  const uint32_t total =
-      current_header_field_.size() + current_header_value_.size() + current_header_map_->byteSize();
+  // Verify that the cached value in byte size exists.
+  ASSERT(current_header_map_->byteSize().has_value());
+  const uint32_t total = current_header_field_.size() + current_header_value_.size() +
+                         current_header_map_->byteSize().value();
   if (total > (max_request_headers_kb_ * 1024)) {
     error_code_ = Http::Code::RequestHeaderFieldsTooLarge;
     sendProtocolError();
@@ -472,6 +474,10 @@
 int ConnectionImpl::onHeadersCompleteBase() {
   ENVOY_CONN_LOG(trace, "headers complete", connection_);
   completeLastHeader();
+  // Validate that the completed HeaderMap's cached byte size exists and is correct.
+  // This assert iterates over the HeaderMap.
+  ASSERT(current_header_map_->byteSize().has_value() &&
+         current_header_map_->byteSize() == current_header_map_->byteSizeInternal());
   if (!(parser_.http_major == 1 && parser_.http_minor == 1)) {
     // This is not necessarily true, but it's good enough since higher layers only care if this is
     // HTTP/1.1 or not.
```
