# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1040_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1040_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1297-1339 of the vulnerable file.

          return;
      } else {
        if (!rfbSendEndOfCU(cl))
          return;
      }

      rfbLog("Continuous updates %s\n",
             cl->continuousUpdates ? "enabled" : "disabled");
      return;
    }

    case rfbFence:
    {
      CARD32 flags;
      char data[64];

      READ(((char *)&msg) + 1, sz_rfbFenceMsg - 1)

      flags = Swap32IfLE(msg.f.flags);

      READ(data, msg.f.length)

      if (msg.f.length > sizeof(data))
        rfbLog("Ignoring fence.  Payload of %d bytes is too large.\n",
               msg.f.length);
      else
        HandleFence(cl, flags, msg.f.length, data);
      return;
    }

    #define EDSERROR(format, args...) {  \
      if (!strlen(errMsg))  \
        snprintf(errMsg, 256, "Desktop resize ERROR: "format"\n", args);  \
      result = rfbEDSResultInvalid;  \
    }

    case rfbSetDesktopSize:
    {
      int i;
      struct xorg_list newScreens;
      rfbClientPtr cl2;
      int result = rfbEDSResultSuccess;
      char errMsg[256] = "\0";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1314,13 +1314,15 @@
 
       flags = Swap32IfLE(msg.f.flags);
 
-      READ(data, msg.f.length)
-
-      if (msg.f.length > sizeof(data))
+      if (msg.f.length > sizeof(data)) {
         rfbLog("Ignoring fence.  Payload of %d bytes is too large.\n",
                msg.f.length);
-      else
+        SKIP(msg.f.length)
+      } else {
+        READ(data, msg.f.length)
         HandleFence(cl, flags, msg.f.length, data);
+      }
+
       return;
     }
 
```
