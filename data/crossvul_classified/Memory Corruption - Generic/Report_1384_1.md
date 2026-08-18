# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 1384_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1384_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 589-608 of the vulnerable file.

              10, true, LineBasedFrameDecoder::TerminatorType::CARRIAGENEWLINE))
    .addBack(test::FrameTester([&](std::unique_ptr<IOBuf> buf) {
        auto sz = buf->computeChainDataLength();
        called++;
        EXPECT_EQ(sz, 1);
      }))
    .finalize();

  auto buf = createZeroedBuffer(3);
  RWPrivateCursor c(buf.get());
  c.write<char>('\n');
  c.write<char>('\r');
  c.write<char>('\n');

  IOBufQueue q(IOBufQueue::cacheChainLength());

  q.append(std::move(buf));
  pipeline->read(q);
  EXPECT_EQ(called, 1);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -606,3 +606,37 @@
   pipeline->read(q);
   EXPECT_EQ(called, 1);
 }
+
+TEST(LineBasedFrameDecoder, CarriageOnly) {
+  auto pipeline = Pipeline<IOBufQueue&, std::unique_ptr<IOBuf>>::create();
+
+  (*pipeline)
+      .addBack(LineBasedFrameDecoder(
+          10, true, LineBasedFrameDecoder::TerminatorType::CARRIAGENEWLINE))
+      .addBack(test::FrameTester([&](std::unique_ptr<IOBuf>) { FAIL(); }))
+      .finalize();
+
+  IOBufQueue q(IOBufQueue::cacheChainLength());
+  q.append(IOBuf::copyBuffer("\raa"));
+  pipeline->read(q);
+}
+
+TEST(LineBasedFrameDecoder, DoubleCarriage) {
+  auto pipeline = Pipeline<IOBufQueue&, std::unique_ptr<IOBuf>>::create();
+  int called = 0;
+
+  (*pipeline)
+      .addBack(LineBasedFrameDecoder(
+          10, true, LineBasedFrameDecoder::TerminatorType::CARRIAGENEWLINE))
+      .addBack(test::FrameTester([&](std::unique_ptr<IOBuf> buf) {
+        auto sz = buf->computeChainDataLength();
+        called++;
+        EXPECT_EQ(sz, 1);
+      }))
+      .finalize();
+
+  IOBufQueue q(IOBufQueue::cacheChainLength());
+  q.append(IOBuf::copyBuffer("\r\r\na\r\n"));
+  pipeline->read(q);
+  EXPECT_EQ(called, 2);
+}
```
