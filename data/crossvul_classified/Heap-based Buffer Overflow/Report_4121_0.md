# CrossVul Fix Pair: Heap-based Buffer Overflow in c
**Pair ID:** 4121_0
**Vulnerability Class:** Heap-based Buffer Overflow
**CWE:** CWE-122
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4121_0`)

## Vulnerability Information & PoC

## Description
Heap-based Buffer Overflow - A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory, generally meaning that the buffer was allocated using a routine ...

## Vulnerable Code
```c
Lines 703-743 of the vulnerable file.

            if ((buffer[0] == 3) && (buffer[1] == 0)) {
                self->packetSize = (buffer[2] * 0x100) + buffer[3];

                if (DEBUG_COTP)
                    printf("TPKT: header complete (msg size = %i)\n", self->packetSize);

                if (self->packetSize > bufferSize) {
                    if (DEBUG_COTP) printf("TPKT: packet too large\n");
                    goto exit_error;
                }
            }
            else {
                if (DEBUG_COTP) printf("TPKT: failed to decode TPKT header.\n");
                goto exit_error;
            }
        }
        else
            goto exit_waiting;
    }

    readBytes = readFromSocket(self, buffer + bufPos, self->packetSize - bufPos);

    if (readBytes < 0)
        goto exit_closed;

    bufPos += readBytes;

    if (bufPos < self->packetSize)
       goto exit_waiting;

    if (DEBUG_COTP) printf("TPKT: message complete (size = %i)\n", self->packetSize);

    self->readBuffer->size = bufPos;
    return TPKT_PACKET_COMPLETE;

exit_closed:
    if (DEBUG_COTP) printf("TPKT: socket closed or socket error\n");
    return TPKT_ERROR;

exit_error:
    if (DEBUG_COTP) printf("TPKT: Error parsing message\n");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -720,6 +720,9 @@
             goto exit_waiting;
     }
 
+    if (self->packetSize <= bufPos)
+        goto exit_error;
+
     readBytes = readFromSocket(self, buffer + bufPos, self->packetSize - bufPos);
 
     if (readBytes < 0)
```
