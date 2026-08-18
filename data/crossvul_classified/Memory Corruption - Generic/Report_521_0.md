# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 521_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `521_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 395-435 of the vulnerable file.

  if (sscanf(pv,rfbProtocolVersionFormat,&major,&minor) != 2 || major != 0 || minor != 0) {
    rfbClientLog("Not a valid VNC repeater (%s)\n",pv);
    return FALSE;
  }

  rfbClientLog("Connected to VNC repeater, using protocol version %d.%d\n", major, minor);

  tmphostlen = snprintf(tmphost, sizeof(tmphost), "%s:%d", destHost, destPort);
  if(tmphostlen < 0 || tmphostlen >= (int)sizeof(tmphost))
    return FALSE; /* snprintf error or output truncated */

  if (!WriteToRFBServer(client, tmphost, tmphostlen + 1))
    return FALSE;

  return TRUE;
}

extern void rfbClientEncryptBytes(unsigned char* bytes, char* passwd);
extern void rfbClientEncryptBytes2(unsigned char *where, const int length, unsigned char *key);

rfbBool
rfbHandleAuthResult(rfbClient* client)
{
    uint32_t authResult=0, reasonLen=0;
    char *reason=NULL;

    if (!ReadFromRFBServer(client, (char *)&authResult, 4)) return FALSE;

    authResult = rfbClientSwap32IfLE(authResult);

    switch (authResult) {
    case rfbVncAuthOK:
      rfbClientLog("VNC authentication succeeded\n");
      return TRUE;
      break;
    case rfbVncAuthFailed:
      if (client->major==3 && client->minor>7)
      {
        /* we have an error following */
        if (!ReadFromRFBServer(client, (char *)&reasonLen, 4)) return FALSE;
        reasonLen = rfbClientSwap32IfLE(reasonLen);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -412,11 +412,29 @@
 extern void rfbClientEncryptBytes(unsigned char* bytes, char* passwd);
 extern void rfbClientEncryptBytes2(unsigned char *where, const int length, unsigned char *key);
 
+static void
+ReadReason(rfbClient* client)
+{
+    uint32_t reasonLen;
+    char *reason;
+
+    if (!ReadFromRFBServer(client, (char *)&reasonLen, 4)) return;
+    reasonLen = rfbClientSwap32IfLE(reasonLen);
+    if(reasonLen > 1<<20) {
+      rfbClientLog("VNC connection failed, but sent reason length of %u exceeds limit of 1MB",(unsigned int)reasonLen);
+      return;
+    }
+    reason = malloc(reasonLen+1);
+    if (!ReadFromRFBServer(client, reason, reasonLen)) { free(reason); return; }
+    reason[reasonLen]=0;
+    rfbClientLog("VNC connection failed: %s\n",reason);
+    free(reason);
+}
+
 rfbBool
 rfbHandleAuthResult(rfbClient* client)
 {
-    uint32_t authResult=0, reasonLen=0;
-    char *reason=NULL;
+    uint32_t authResult=0;
 
     if (!ReadFromRFBServer(client, (char *)&authResult, 4)) return FALSE;
 
@@ -431,13 +449,7 @@
       if (client->major==3 && client->minor>7)
       {
         /* we have an error following */
-        if (!ReadFromRFBServer(client, (char *)&reasonLen, 4)) return FALSE;
-        reasonLen = rfbClientSwap32IfLE(reasonLen);
-        reason = malloc((uint64_t)reasonLen+1);
-        if (!ReadFromRFBServer(client, reason, reasonLen)) { free(reason); return FALSE; }
-        reason[reasonLen]=0;
-        rfbClientLog("VNC connection failed: %s\n",reason);
-        free(reason);
+        ReadReason(client);
         return FALSE;
       }
       rfbClientLog("VNC authentication failed\n");
@@ -452,21 +464,6 @@
     return FALSE;
 }
 
-static void
-ReadReason(rfbClient* client)
-{
-    uint32_t reasonLen;
-    char *reason;
-
-    /* we have an error following */
-    if (!ReadFromRFBServer(client, (char *)&reasonLen, 4)) return;
-    reasonLen = rfbClientSwap32IfLE(reasonLen);
-    reason = malloc((uint64_t)reasonLen+1);
-    if (!ReadFromRFBServer(client, reason, reasonLen)) { free(reason); return; }
-    reason[reasonLen]=0;
-    rfbClientLog("VNC connection failed: %s\n",reason);
-    free(reason);
-}
 
 static rfbBool
 ReadSupportedSecurityType(rfbClient* client, uint32_t *result, rfbBool subAuth)
```
