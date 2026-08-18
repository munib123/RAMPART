# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in java
**Pair ID:** 2139_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2139_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```java
Lines 1251-1291 of the vulnerable file.

                SSLEngineResult result;
                boolean needsHandshake = false;
                synchronized (handshakeLock) {
                    if (!handshaken && !handshaking &&
                        !engine.getUseClientMode() &&
                        !engine.isInboundDone() && !engine.isOutboundDone()) {
                        needsHandshake = true;
                    }
                }

                if (needsHandshake) {
                    handshake();
                }

                synchronized (handshakeLock) {
                    // Decrypt at least one record in the inbound network buffer.
                    // It is impossible to consume no record here because we made sure the inbound network buffer
                    // always contain at least one record in decode().  Therefore, if SSLEngine.unwrap() returns
                    // BUFFER_OVERFLOW, it is always resolved by retrying after emptying the application buffer.
                    for (;;) {
                        try {
                            result = engine.unwrap(nioInNetBuf, nioOutAppBuf);
                            switch (result.getStatus()) {
                                case CLOSED:
                                    // notify about the CLOSED state of the SSLEngine. See #137
                                    sslEngineCloseFuture.setClosed();
                                    break;
                                case BUFFER_OVERFLOW:
                                    // Flush the unwrapped data in the outAppBuf into frame and try again.
                                    // See the finally block.
                                    continue;
                            }

                            break;
                        } finally {
                            nioOutAppBuf.flip();

                            // Sync the offset of the inbound buffer.
                            nettyInNetBuf.readerIndex(
                                    nettyInNetBufStartOffset + nioInNetBuf.position() - nioInNetBufStartOffset);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1268,8 +1268,18 @@
                     // always contain at least one record in decode().  Therefore, if SSLEngine.unwrap() returns
                     // BUFFER_OVERFLOW, it is always resolved by retrying after emptying the application buffer.
                     for (;;) {
+                        final int outAppBufSize = engine.getSession().getApplicationBufferSize();
+                        final ByteBuffer outAppBuf;
+                        if (nioOutAppBuf.capacity() < outAppBufSize) {
+                            // SSLEngine wants a buffer larger than what the pool can provide.
+                            // Allocate a temporary heap buffer.
+                            outAppBuf = ByteBuffer.allocate(outAppBufSize);
+                        } else {
+                            outAppBuf = nioOutAppBuf;
+                        }
+
                         try {
-                            result = engine.unwrap(nioInNetBuf, nioOutAppBuf);
+                            result = engine.unwrap(nioInNetBuf, outAppBuf);
                             switch (result.getStatus()) {
                                 case CLOSED:
                                     // notify about the CLOSED state of the SSLEngine. See #137
@@ -1283,21 +1293,21 @@
 
                             break;
                         } finally {
-                            nioOutAppBuf.flip();
+                            outAppBuf.flip();
 
                             // Sync the offset of the inbound buffer.
                             nettyInNetBuf.readerIndex(
                                     nettyInNetBufStartOffset + nioInNetBuf.position() - nioInNetBufStartOffset);
 
                             // Copy the unwrapped data into a smaller buffer.
-                            if (nioOutAppBuf.hasRemaining()) {
+                            if (outAppBuf.hasRemaining()) {
                                 if (nettyOutAppBuf == null) {
                                     ChannelBufferFactory factory = ctx.getChannel().getConfig().getBufferFactory();
                                     nettyOutAppBuf = factory.getBuffer(initialNettyOutAppBufCapacity);
                                 }
-                                nettyOutAppBuf.writeBytes(nioOutAppBuf);
+                                nettyOutAppBuf.writeBytes(outAppBuf);
                             }
-                            nioOutAppBuf.clear();
+                            outAppBuf.clear();
                         }
                     }
 
```
