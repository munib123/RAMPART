# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 4059_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4059_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 45-85 of the vulnerable file.


rfbBool errorMessageOnReadFailure = TRUE;

/*
 * ReadFromRFBServer is called whenever we want to read some data from the RFB
 * server.  It is non-trivial for two reasons:
 *
 * 1. For efficiency it performs some intelligent buffering, avoiding invoking
 *    the read() system call too often.  For small chunks of data, it simply
 *    copies the data out of an internal buffer.  For large amounts of data it
 *    reads directly into the buffer provided by the caller.
 *
 * 2. Whenever read() would block, it invokes the Xt event dispatching
 *    mechanism to process X events.  In fact, this is the only place these
 *    events are processed, as there is no XtAppMainLoop in the program.
 */

rfbBool
ReadFromRFBServer(rfbClient* client, char *out, unsigned int n)
{
#undef DEBUG_READ_EXACT
#ifdef DEBUG_READ_EXACT
	char* oout=out;
	unsigned int nn=n;
	rfbClientLog("ReadFromRFBServer %d bytes\n",n);
#endif

  /* Handle attempts to write to NULL out buffer that might occur
     when an outside malloc() fails. For instance, memcpy() to NULL
     results in undefined behaviour and probably memory corruption.*/
  if(!out)
    return FALSE;

  if (client->serverPort==-1) {
    /* vncrec playing */
    rfbVNCRec* rec = client->vncRec;
    struct timeval tv;

    if (rec->readTimestamp) {
      rec->readTimestamp = FALSE;
      if (!fread(&tv,sizeof(struct timeval),1,rec->file))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,6 +62,8 @@
 rfbBool
 ReadFromRFBServer(rfbClient* client, char *out, unsigned int n)
 {
+  const int USECS_WAIT_PER_RETRY = 100000;
+  int retries = 0;
 #undef DEBUG_READ_EXACT
 #ifdef DEBUG_READ_EXACT
 	char* oout=out;
@@ -151,10 +153,16 @@
       if (i <= 0) {
 	if (i < 0) {
 	  if (errno == EWOULDBLOCK || errno == EAGAIN) {
+	    if (client->readTimeout > 0 &&
+		++retries > (client->readTimeout * 1000 * 1000 / USECS_WAIT_PER_RETRY))
+	    {
+	      rfbClientLog("Connection timed out\n");
+	      return FALSE;
+	    }
 	    /* TODO:
 	       ProcessXtEvents();
 	    */
-	    WaitForMessage(client, 100000);
+	    WaitForMessage(client, USECS_WAIT_PER_RETRY);
 	    i = 0;
 	  } else {
 	    rfbClientErr("read (%d: %s)\n",errno,strerror(errno));
@@ -194,10 +202,16 @@
 	  errno=WSAGetLastError();
 #endif
 	  if (errno == EWOULDBLOCK || errno == EAGAIN) {
+	    if (client->readTimeout > 0 &&
+		++retries > (client->readTimeout * 1000 * 1000 / USECS_WAIT_PER_RETRY))
+	    {
+		rfbClientLog("Connection timed out\n");
+		return FALSE;
+	    }
 	    /* TODO:
 	       ProcessXtEvents();
 	    */
-	    WaitForMessage(client, 100000);
+	    WaitForMessage(client, USECS_WAIT_PER_RETRY);
 	    i = 0;
 	  } else {
 	    rfbClientErr("read (%s)\n",strerror(errno));
```
