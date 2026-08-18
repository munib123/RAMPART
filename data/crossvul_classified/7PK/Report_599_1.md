# CrossVul Fix Pair: 7PK in cpp
**Pair ID:** 599_1
**Vulnerability Class:** 7PK
**CWE:** CWE-388
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `599_1`)

## Vulnerability Information & PoC

## Description
7PK - Errors

## Vulnerable Code
```cpp
Lines 1360-1400 of the vulnerable file.

  EXPECT_EQ(callbacks_.streamErrors, 0);
  EXPECT_EQ(callbacks_.sessionErrors, 0);
}

TEST_F(HTTP2CodecTest, BadHeaderPriority) {
  HTTPMessage req = getGetRequest();
  req.setHTTP2Priority(HTTPMessage::HTTPPriority(0, false, 7));
  upstreamCodec_.generateHeader(output_, 1, req, true /* eom */);

  // hack ingress with cirular dep
  EXPECT_TRUE(parse([&] (IOBuf* ingress) {
        folly::io::RWPrivateCursor c(ingress);
        c.skip(http2::kFrameHeaderSize + http2::kConnectionPreface.length());
        c.writeBE<uint32_t>(1);
      }));

  EXPECT_EQ(callbacks_.streamErrors, 1);
  EXPECT_EQ(callbacks_.sessionErrors, 0);
}

TEST_F(HTTP2CodecTest, BadPriority) {
  auto pri = HTTPMessage::HTTPPriority(0, true, 1);
  upstreamCodec_.generatePriority(output_, 1, pri);

  // hack ingress with cirular dep
  EXPECT_TRUE(parse([&] (IOBuf* ingress) {
        folly::io::RWPrivateCursor c(ingress);
        c.skip(http2::kFrameHeaderSize + http2::kConnectionPreface.length());
        c.writeBE<uint32_t>(1);
      }));

  EXPECT_EQ(callbacks_.streamErrors, 1);
  EXPECT_EQ(callbacks_.sessionErrors, 0);
}

class DummyQueue: public HTTPCodec::PriorityQueue {
 public:
  DummyQueue() {}
  ~DummyQueue() override {}
  void addPriorityNode(HTTPCodec::StreamID id, HTTPCodec::StreamID) override {
    nodes_.push_back(id);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1377,6 +1377,30 @@
   EXPECT_EQ(callbacks_.sessionErrors, 0);
 }
 
+TEST_F(HTTP2CodecTest, DuplicateBadHeaderPriority) {
+  // Sent an initial header with a circular dependency
+  HTTPMessage req = getGetRequest();
+  req.setHTTP2Priority(HTTPMessage::HTTPPriority(0, false, 7));
+  upstreamCodec_.generateHeader(output_, 1, req, true /* eom */);
+
+  // Hack ingress with circular dependency.
+  EXPECT_TRUE(parse([&](IOBuf* ingress) {
+    folly::io::RWPrivateCursor c(ingress);
+    c.skip(http2::kFrameHeaderSize + http2::kConnectionPreface.length());
+    c.writeBE<uint32_t>(1);
+  }));
+
+  EXPECT_EQ(callbacks_.streamErrors, 1);
+  EXPECT_EQ(callbacks_.sessionErrors, 0);
+
+  // On the same stream, send another request.
+  HTTPMessage nextRequest = getGetRequest();
+  upstreamCodec_.generateHeader(output_, 1, nextRequest, true /* eom */);
+  parse();
+  EXPECT_EQ(callbacks_.streamErrors, 2);
+  EXPECT_EQ(callbacks_.sessionErrors, 0);
+}
+
 TEST_F(HTTP2CodecTest, BadPriority) {
   auto pri = HTTPMessage::HTTPPriority(0, true, 1);
   upstreamCodec_.generatePriority(output_, 1, pri);
```
