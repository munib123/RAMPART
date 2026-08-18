# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 600_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `600_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 2128-2147 of the vulnerable file.

  trailers.add("x-huge-trailer",
               std::string(http2::kMaxFramePayloadLengthMin, '!'));
  downstreamCodec_.generateTrailers(output_, 1, trailers);
  // empirically determined the size of continuation frame, and strip it
  output_.trimEnd(http2::kFrameHeaderSize + 4132);

  // insert a non-continuation (but otherwise valid) frame
  http2::writeGoaway(output_, 17, ErrorCode::ENHANCE_YOUR_CALM);

  parseUpstream();

  EXPECT_EQ(callbacks_.messageBegin, 1);
  EXPECT_EQ(callbacks_.headersComplete, 1);
  EXPECT_EQ(callbacks_.messageComplete, 0);
  EXPECT_EQ(callbacks_.streamErrors, 0);
  EXPECT_EQ(callbacks_.sessionErrors, 1);
#ifndef NDEBUG
  EXPECT_EQ(upstreamCodec_.getReceivedFrameCount(), 4);
#endif
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2145,3 +2145,28 @@
   EXPECT_EQ(upstreamCodec_.getReceivedFrameCount(), 4);
 #endif
 }
+
+TEST_F(HTTP2CodecTest, TrailersNotLatest) {
+  HTTPMessage req = getGetRequest("/guacamole");
+  req.getHeaders().add(HTTP_HEADER_USER_AGENT, "coolio");
+  upstreamCodec_.generateHeader(output_, 1, req);
+  upstreamCodec_.generateHeader(output_, 3, req);
+
+  HTTPHeaders trailers;
+  trailers.add("x-trailer-1", "pico-de-gallo");
+  upstreamCodec_.generateTrailers(output_, 1, trailers);
+  upstreamCodec_.generateHeader(output_, 3, req);
+
+  parse();
+
+  EXPECT_EQ(callbacks_.messageBegin, 2);
+  EXPECT_EQ(callbacks_.headersComplete, 2);
+  EXPECT_EQ(callbacks_.bodyCalls, 0);
+  EXPECT_EQ(callbacks_.trailers, 1);
+  EXPECT_NE(nullptr, callbacks_.msg->getTrailers());
+  EXPECT_EQ("pico-de-gallo",
+            callbacks_.msg->getTrailers()->getSingleOrEmpty("x-trailer-1"));
+  EXPECT_EQ(callbacks_.messageComplete, 1);
+  EXPECT_EQ(callbacks_.streamErrors, 1);
+  EXPECT_EQ(callbacks_.sessionErrors, 0);
+}
```
