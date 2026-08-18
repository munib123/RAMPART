# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 1029_3
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1029_3`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 489-529 of the vulnerable file.

    std::chrono::milliseconds request_timeout_ms_ = connection_manager_.config_.requestTimeout();
    request_timer_ = connection_manager.read_callbacks_->connection().dispatcher().createTimer(
        [this]() -> void { onRequestTimeout(); });
    request_timer_->enableTimer(request_timeout_ms_, this);
  }

  stream_info_.setRequestedServerName(
      connection_manager_.read_callbacks_->connection().requestedServerName());
}

ConnectionManagerImpl::ActiveStream::~ActiveStream() {
  stream_info_.onRequestComplete();

  // A downstream disconnect can be identified for HTTP requests when the upstream returns with a 0
  // response code and when no other response flags are set.
  if (!stream_info_.hasAnyResponseFlag() && !stream_info_.responseCode()) {
    stream_info_.setResponseFlag(StreamInfo::ResponseFlag::DownstreamConnectionTermination);
  }

  connection_manager_.stats_.named_.downstream_rq_active_.dec();
  for (const AccessLog::InstanceSharedPtr& access_log : connection_manager_.config_.accessLogs()) {
    access_log->log(request_headers_.get(), response_headers_.get(), response_trailers_.get(),
                    stream_info_);
  }
  for (const auto& log_handler : access_log_handlers_) {
    log_handler->log(request_headers_.get(), response_headers_.get(), response_trailers_.get(),
                     stream_info_);
  }

  if (stream_info_.healthCheck()) {
    connection_manager_.config_.tracingStats().health_check_.inc();
  }

  if (active_span_) {
    Tracing::HttpTracerUtility::finalizeDownstreamSpan(
        *active_span_, request_headers_.get(), response_headers_.get(), response_trailers_.get(),
        stream_info_, *this);
  }
  if (state_.successful_upgrade_) {
    connection_manager_.stats_.named_.downstream_cx_upgrades_active_.dec();
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -506,6 +506,18 @@
   }
 
   connection_manager_.stats_.named_.downstream_rq_active_.dec();
+  // Refresh byte sizes of the HeaderMaps before logging.
+  // TODO(asraa): Remove this when entries in HeaderMap can no longer be modified by reference and
+  // HeaderMap holds an accurate internal byte size count.
+  if (request_headers_ != nullptr) {
+    request_headers_->refreshByteSize();
+  }
+  if (response_headers_ != nullptr) {
+    response_headers_->refreshByteSize();
+  }
+  if (response_trailers_ != nullptr) {
+    response_trailers_->refreshByteSize();
+  }
   for (const AccessLog::InstanceSharedPtr& access_log : connection_manager_.config_.accessLogs()) {
     access_log->log(request_headers_.get(), response_headers_.get(), response_trailers_.get(),
                     stream_info_);
@@ -717,14 +729,6 @@
                      StreamInfo::ResponseCodeDetails::get().MissingHost);
       return;
     }
-  }
-
-  ASSERT(connection_manager_.config_.maxRequestHeadersKb() > 0);
-  if (request_headers_->byteSize() > (connection_manager_.config_.maxRequestHeadersKb() * 1024)) {
-    sendLocalReply(Grpc::Common::hasGrpcContentType(*request_headers_),
-                   Code::RequestHeaderFieldsTooLarge, "", nullptr, is_head_request_, absl::nullopt,
-                   StreamInfo::ResponseCodeDetails::get().RequestHeadersTooLarge);
-    return;
   }
 
   // Currently we only support relative paths at the application layer. We expect the codec to have
```
