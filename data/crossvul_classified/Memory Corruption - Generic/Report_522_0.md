# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 522_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `522_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1444-1484 of the vulnerable file.

    }
#ifdef WIN32
    if (findHandle != INVALID_HANDLE_VALUE)
    {
        FindClose(findHandle);
    }
#else
    closedir(dirp);
#endif
    /* End of the transfer */
    return rfbSendFileTransferMessage(cl, rfbDirPacket, 0, 0, 0, NULL);
}


char *rfbProcessFileTransferReadBuffer(rfbClientPtr cl, uint32_t length)
{
    char *buffer=NULL;
    int   n=0;

    FILEXFER_ALLOWED_OR_CLOSE_AND_RETURN("", cl, NULL);
    /*
    rfbLog("rfbProcessFileTransferReadBuffer(%dlen)\n", length);
    */
    if (length>0) {
        buffer=malloc((uint64_t)length+1);
        if (buffer!=NULL) {
            if ((n = rfbReadExact(cl, (char *)buffer, length)) <= 0) {
                if (n != 0)
                    rfbLogPerror("rfbProcessFileTransferReadBuffer: read");
                rfbCloseClient(cl);
                /* NOTE: don't forget to free(buffer) if you return early! */
                if (buffer!=NULL) free(buffer);
                return NULL;
            }
            /* Null Terminate */
            buffer[length]=0;
        }
    }
    return buffer;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1461,11 +1461,21 @@
     int   n=0;
 
     FILEXFER_ALLOWED_OR_CLOSE_AND_RETURN("", cl, NULL);
+
     /*
-    rfbLog("rfbProcessFileTransferReadBuffer(%dlen)\n", length);
+       We later alloc length+1, which might wrap around on 32-bit systems if length equals
+       0XFFFFFFFF, i.e. SIZE_MAX for 32-bit systems. On 64-bit systems, a length of 0XFFFFFFFF
+       will safely be allocated since this check will never trigger and malloc() can digest length+1
+       without problems as length is a uint32_t.
     */
+    if(length == SIZE_MAX) {
+	rfbErr("rfbProcessFileTransferReadBuffer: too big file transfer length requested: %u", (unsigned int)length);
+	rfbCloseClient(cl);
+	return NULL;
+    }
+
     if (length>0) {
-        buffer=malloc((uint64_t)length+1);
+        buffer=malloc((size_t)length+1);
         if (buffer!=NULL) {
             if ((n = rfbReadExact(cl, (char *)buffer, length)) <= 0) {
                 if (n != 0)
```
