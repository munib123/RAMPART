# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 519_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `519_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1207-1248 of the vulnerable file.

      if (authHandled) break;
    }
    rfbClientLog("Unknown authentication scheme from VNC server: %d\n",
	    (int)authScheme);
    return FALSE;
  }

  ci.shared = (client->appData.shareDesktop ? 1 : 0);

  if (!WriteToRFBServer(client,  (char *)&ci, sz_rfbClientInitMsg)) return FALSE;

  if (!ReadFromRFBServer(client, (char *)&client->si, sz_rfbServerInitMsg)) return FALSE;

  client->si.framebufferWidth = rfbClientSwap16IfLE(client->si.framebufferWidth);
  client->si.framebufferHeight = rfbClientSwap16IfLE(client->si.framebufferHeight);
  client->si.format.redMax = rfbClientSwap16IfLE(client->si.format.redMax);
  client->si.format.greenMax = rfbClientSwap16IfLE(client->si.format.greenMax);
  client->si.format.blueMax = rfbClientSwap16IfLE(client->si.format.blueMax);
  client->si.nameLength = rfbClientSwap32IfLE(client->si.nameLength);

  /* To guard against integer wrap-around, si.nameLength is cast to 64 bit */
  client->desktopName = malloc((uint64_t)client->si.nameLength + 1);
  if (!client->desktopName) {
    rfbClientLog("Error allocating memory for desktop name, %lu bytes\n",
            (unsigned long)client->si.nameLength);
    return FALSE;
  }

  if (!ReadFromRFBServer(client, client->desktopName, client->si.nameLength)) return FALSE;

  client->desktopName[client->si.nameLength] = 0;

  rfbClientLog("Desktop name \"%s\"\n",client->desktopName);

  rfbClientLog("Connected to VNC server, using protocol version %d.%d\n",
	  client->major, client->minor);

  rfbClientLog("VNC server default format:\n");
  PrintPixelFormat(&client->si.format);

  return TRUE;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1224,8 +1224,12 @@
   client->si.format.blueMax = rfbClientSwap16IfLE(client->si.format.blueMax);
   client->si.nameLength = rfbClientSwap32IfLE(client->si.nameLength);
 
-  /* To guard against integer wrap-around, si.nameLength is cast to 64 bit */
-  client->desktopName = malloc((uint64_t)client->si.nameLength + 1);
+  if (client->si.nameLength > 1<<20) {
+      rfbClientErr("Too big desktop name length sent by server: %u B > 1 MB\n", (unsigned int)client->si.nameLength);
+      return FALSE;
+  }
+
+  client->desktopName = malloc(client->si.nameLength + 1);
   if (!client->desktopName) {
     rfbClientLog("Error allocating memory for desktop name, %lu bytes\n",
             (unsigned long)client->si.nameLength);
```
