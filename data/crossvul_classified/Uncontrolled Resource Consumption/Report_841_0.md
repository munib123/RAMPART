# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 841_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `841_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 63-103 of the vulnerable file.

  void handleError(folly::IOBuf& buffer);
  /**
   * Read value data.
   * It uses remainingIOBufLength_ to determine how much we need to read. It
   * will also update that variable and currentIOBuf_ accordingly.
   *
   * @return true iff the value was completely read.
   */
  bool readValue(folly::IOBuf& buffer, folly::IOBuf& to);
  bool readValue(folly::IOBuf& buffer, folly::Optional<folly::IOBuf>& to);

  static void appendKeyPiece(
      const folly::IOBuf& from,
      folly::IOBuf& to,
      const char* posStart,
      const char* posEnd);
  static void trimIOBufToRange(
      folly::IOBuf& buffer,
      const char* posStart,
      const char* posEnd);

  std::string currentErrorDescription_;

  uint64_t currentUInt_{0};

  folly::IOBuf* currentIOBuf_{nullptr};
  size_t remainingIOBufLength_{0};
  State state_{State::UNINIT};
  bool negative_{false};

  // Variables used by ragel.
  int savedCs_;
  int errorCs_;
  const char* p_{nullptr};
  const char* pe_{nullptr};
};

class McClientAsciiParser : public McAsciiParserBase {
 public:
  /**
   * Consume given IOBuf.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,6 +81,9 @@
       const char* posStart,
       const char* posEnd);
 
+  // limit the value size.
+  static constexpr uint32_t maxValueBytes = 1 * 1024 * 1024 * 1024; // 1GB
+
   std::string currentErrorDescription_;
 
   uint64_t currentUInt_{0};
```
