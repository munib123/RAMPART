# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1436_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1436_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 285-326 of the vulnerable file.

#else
#error "please provide an implementation of obtain_nonce() for your platform"
#endif /* _WIN32 */

static int
init_device (u2fh_devs * devs, struct u2fdevice *dev)
{
  unsigned char resp[1024];
  unsigned char nonce[8];
  if (obtain_nonce(nonce) != 0)
    {
      return U2FH_TRANSPORT_ERROR;
    }
  size_t resplen = sizeof (resp);
  dev->cid = CID_BROADCAST;

  if (u2fh_sendrecv
      (devs, dev->id, U2FHID_INIT, nonce, sizeof (nonce), resp,
       &resplen) == U2FH_OK)
    {
      U2FHID_INIT_RESP initresp;
      if (resplen > sizeof (initresp))
	{
	  return U2FH_MEMORY_ERROR;
	}
      memcpy (&initresp, resp, resplen);
      dev->cid = initresp.cid;
      dev->versionInterface = initresp.versionInterface;
      dev->versionMajor = initresp.versionMajor;
      dev->versionMinor = initresp.versionMinor;
      dev->capFlags = initresp.capFlags;
    }
  else
    {
      return U2FH_TRANSPORT_ERROR;
    }
  return U2FH_OK;
}

static int
ping_device (u2fh_devs * devs, unsigned index)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -302,17 +302,29 @@
       (devs, dev->id, U2FHID_INIT, nonce, sizeof (nonce), resp,
        &resplen) == U2FH_OK)
     {
-      U2FHID_INIT_RESP initresp;
-      if (resplen > sizeof (initresp))
-	{
-	  return U2FH_MEMORY_ERROR;
-	}
-      memcpy (&initresp, resp, resplen);
-      dev->cid = initresp.cid;
-      dev->versionInterface = initresp.versionInterface;
-      dev->versionMajor = initresp.versionMajor;
-      dev->versionMinor = initresp.versionMinor;
-      dev->capFlags = initresp.capFlags;
+      int offs = sizeof (nonce);
+      /* the response has to be atleast 17 bytes, if it's more we discard that */
+      if (resplen < 17)
+	{
+	  return U2FH_SIZE_ERROR;
+	}
+
+      /* incoming and outgoing nonce has to match */
+      if (memcmp (nonce, resp, sizeof (nonce)) != 0)
+	{
+	  return U2FH_TRANSPORT_ERROR;
+	}
+
+      dev->cid =
+	resp[offs] << 24 | resp[offs + 1] << 16 | resp[offs +
+						       2] << 8 | resp[offs +
+								      3];
+      offs += 4;
+      dev->versionInterface = resp[offs++];
+      dev->versionMajor = resp[offs++];
+      dev->versionMinor = resp[offs++];
+      dev->versionBuild = resp[offs++];
+      dev->capFlags = resp[offs++];
     }
   else
     {
```
