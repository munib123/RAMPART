# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1029_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1029_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 61-101 of the vulnerable file.

  /**
   * Evaluate whether an access log should be written based on request and response data.
   * @return TRUE if the log should be written.
   */
  virtual bool evaluate(const StreamInfo::StreamInfo& info, const Http::HeaderMap& request_headers,
                        const Http::HeaderMap& response_headers,
                        const Http::HeaderMap& response_trailers) PURE;
};

using FilterPtr = std::unique_ptr<Filter>;

/**
 * Abstract access logger for requests and connections.
 */
class Instance {
public:
  virtual ~Instance() = default;

  /**
   * Log a completed request.
   * @param request_headers supplies the incoming request headers after filtering.
   * @param response_headers supplies response headers.
   * @param response_trailers supplies response trailers.
   * @param stream_info supplies additional information about the request not
   * contained in the request headers.
   */
  virtual void log(const Http::HeaderMap* request_headers, const Http::HeaderMap* response_headers,
                   const Http::HeaderMap* response_trailers,
                   const StreamInfo::StreamInfo& stream_info) PURE;
};

using InstanceSharedPtr = std::shared_ptr<Instance>;

/**
 * Interface for access log formatter.
 * Formatters provide a complete access log output line for the given headers/trailers/stream.
 */
class Formatter {
public:
  virtual ~Formatter() = default;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,6 +78,10 @@
 
   /**
    * Log a completed request.
+   * Prior to logging, call refreshByteSize() on HeaderMaps to ensure that an accurate byte size
+   * count is logged.
+   * TODO(asraa): Remove refreshByteSize() requirement when entries in HeaderMap can no longer be
+   * modified by reference and headerMap holds an accurate internal byte size count.
    * @param request_headers supplies the incoming request headers after filtering.
    * @param response_headers supplies response headers.
    * @param response_trailers supplies response trailers.
```
