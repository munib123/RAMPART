# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 197_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `197_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 380-420 of the vulnerable file.


               mConnState = NewMessage;
               mBuffer = 0;
               if (overHang > 0) 
               {
                  // The next message has been partially read.
                  size_t size = overHang*3/2;
                  if (size < ConnectionBase::ChunkSize)
                  {
                     size = ConnectionBase::ChunkSize;
                  }
                  char* newBuffer = MsgHeaderScanner::allocateBuffer((int)size);
                  memcpy(newBuffer,
                         unprocessedCharPtr + contentLength,
                         overHang);
                  mBuffer = newBuffer;
                  mBufferPos = 0;
                  mBufferSize = size;
                  
                  DebugLog (<< "Extra bytes after message: " << overHang);
                  DebugLog (<< Data(mBuffer, overHang));
                  
                  bytesRead = overHang;
               }

               // The message body is complete.
               mMessage->setBody(unprocessedCharPtr, (UInt32)contentLength);
               CongestionManager::RejectionBehavior b=mTransport->getRejectionBehaviorForIncoming();
               if (b==CongestionManager::REJECTING_NON_ESSENTIAL
                     || (b==CongestionManager::REJECTING_NEW_WORK
                        && mMessage->isRequest()))
               {
                  UInt32 expectedWait(mTransport->getExpectedWaitForIncoming());
                  // .bwc. If this fifo is REJECTING_NEW_WORK, we will drop
                  // requests but not responses ( ?bwc? is this right for ACK?). 
                  // If we are REJECTING_NON_ESSENTIAL, 
                  // we reject all incoming work, since losing something from the 
                  // wire will not cause instability or leaks (see 
                  // CongestionManager.hxx)
                  
                  // .bwc. This handles all appropriate checking for whether
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -397,7 +397,7 @@
                   mBufferSize = size;
                   
                   DebugLog (<< "Extra bytes after message: " << overHang);
-                  DebugLog (<< Data(mBuffer, overHang));
+                  //DebugLog (<< Data(mBuffer, overHang));
                   
                   bytesRead = overHang;
                }
@@ -471,11 +471,36 @@
          }
 
          mBufferPos += bytesRead;
-         if (mBufferPos == contentLength)
-         {
+         if (mBufferPos >= contentLength)
+         {
+            int overHang = mBufferPos - (int)contentLength;
+            char *overHangStart = mBuffer + contentLength;
+
             mMessage->addBuffer(mBuffer);
             mMessage->setBody(mBuffer, (UInt32)contentLength);
-            mBuffer=0;
+            mConnState = NewMessage;
+            mBuffer = 0;
+
+            if (overHang > 0)
+            {
+                // The next message has been partially read.
+                size_t size = overHang * 3 / 2;
+                if (size < ConnectionBase::ChunkSize)
+                {
+                    size = ConnectionBase::ChunkSize;
+                }
+                char* newBuffer = MsgHeaderScanner::allocateBuffer((int)size);
+                memcpy(newBuffer, overHangStart, overHang);
+                mBuffer = newBuffer;
+                mBufferPos = 0;
+                mBufferSize = size;
+
+                DebugLog(<< "Extra bytes after message: " << overHang);
+                //DebugLog(<< Data(mBuffer, overHang));
+
+                bytesRead = overHang;
+            }
+
             // .bwc. basicCheck takes up substantial CPU. Don't bother doing it
             // if we're overloaded.
             CongestionManager::RejectionBehavior b=mTransport->getRejectionBehaviorForIncoming();
@@ -515,11 +540,16 @@
                mTransport->pushRxMsgUp(mMessage);
                mMessage = 0;
             }
-            mConnState = NewMessage;
+            
+            if (overHang > 0) 
+            {
+               goto start;
+            }
          }
          else if (mBufferPos == mBufferSize)
          {
-            // .bwc. We've filled our buffer; go ahead and make more room.
+            // .bwc. We've filled our buffer and haven't read contentLength bytes yet; go ahead and make more room.
+            assert(contentLength >= mBufferSize);
             size_t newSize = resipMin(mBufferSize*3/2, contentLength);
             char* newBuffer = 0;
             try
```
