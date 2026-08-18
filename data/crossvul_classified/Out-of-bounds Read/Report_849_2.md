# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 849_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `849_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 372-412 of the vulnerable file.

         it != buffers.end();
         ++it) {
      it->free();
    }
    currentBuffer.free();
  }

  void getReadBuffer(void** bufReturn, size_t* lenReturn) override {
    if (!currentBuffer.buffer) {
      currentBuffer.allocate(4096);
    }
    *bufReturn = currentBuffer.buffer;
    *lenReturn = currentBuffer.length;
  }

  void readDataAvailable(size_t len) noexcept override {
    std::cerr << "readDataAvailable, len " << len << std::endl;

    currentBuffer.length = len;

    wcb_->setSocket(socket_);

    // Write back the same data.
    socket_->write(wcb_, currentBuffer.buffer, len, writeFlags);

    buffers.push_back(currentBuffer);
    currentBuffer.reset();
    state = STATE_SUCCEEDED;
  }

  /**
   * These flags will be used when writing the read data back to the socket.
   */
  void setWriteFlags(folly::WriteFlags flags) {
    writeFlags = flags;
  }

  class Buffer {
   public:
    Buffer() : buffer(nullptr), length(0) {}
    Buffer(char* buf, size_t len) : buffer(buf), length(len) {}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -389,7 +389,9 @@
 
     currentBuffer.length = len;
 
-    wcb_->setSocket(socket_);
+    if (wcb_) {
+      wcb_->setSocket(socket_);
+    }
 
     // Write back the same data.
     socket_->write(wcb_, currentBuffer.buffer, len, writeFlags);
```
