# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3301_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3301_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 778-818 of the vulnerable file.

	static char msg_buffer[20];
	register unsigned char i;

	alarm(2);
	for (; !XCheckTypedWindowEvent(disp, my_ipc_win, ClientMessage, &ev)
	     && !timeout;);
	alarm(0);
	if (ev.xany.type != ClientMessage) {
		return(IPC_TIMEOUT);
	}
	for (i = 0; i < 20; i++) {
		msg_buffer[i] = ev.xclient.data.b[i];
	}
	return(msg_buffer + 8);
}

char *enl_ipc_get(const char *msg_data)
{

	static char *message = NULL;
	static unsigned short len = 0;
	char buff[13], *ret_msg = NULL;
	register unsigned char i;
	unsigned char blen;

	if (msg_data == IPC_TIMEOUT) {
		return(IPC_TIMEOUT);
	}
	for (i = 0; i < 12; i++) {
		buff[i] = msg_data[i];
	}
	buff[12] = 0;
	blen = strlen(buff);
	if (message != NULL) {
		len += blen;
		message = (char *) erealloc(message, len + 1);
		strcat(message, buff);
	} else {
		len = blen;
		message = (char *) emalloc(len + 1);
		strcpy(message, buff);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -795,7 +795,7 @@
 {
 
 	static char *message = NULL;
-	static unsigned short len = 0;
+	static size_t len = 0;
 	char buff[13], *ret_msg = NULL;
 	register unsigned char i;
 	unsigned char blen;
```
