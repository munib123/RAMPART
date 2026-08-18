# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 520_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `520_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 2200-2240 of the vulnerable file.

    break;
  }

  case rfbBell:
  {
    client->Bell(client);

    break;
  }

  case rfbServerCutText:
  {
    char *buffer;

    if (!ReadFromRFBServer(client, ((char *)&msg) + 1,
			   sz_rfbServerCutTextMsg - 1))
      return FALSE;

    msg.sct.length = rfbClientSwap32IfLE(msg.sct.length);

    buffer = malloc((uint64_t)msg.sct.length+1);

    if (!ReadFromRFBServer(client, buffer, msg.sct.length)) {
      free(buffer);
      return FALSE;
    }

    buffer[msg.sct.length] = 0;

    if (client->GotXCutText)
      client->GotXCutText(client, buffer, msg.sct.length);

    free(buffer);

    break;
  }

  case rfbTextChat:
  {
      char *buffer=NULL;
      if (!ReadFromRFBServer(client, ((char *)&msg) + 1,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2217,6 +2217,11 @@
 
     msg.sct.length = rfbClientSwap32IfLE(msg.sct.length);
 
+    if (msg.sct.length > 1<<20) {
+	    rfbClientErr("Ignoring too big cut text length sent by server: %u B > 1 MB\n", (unsigned int)msg.sct.length);
+	    return FALSE;
+    }  
+
     buffer = malloc((uint64_t)msg.sct.length+1);
 
     if (!ReadFromRFBServer(client, buffer, msg.sct.length)) {
```
