# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 4059_2
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4059_2`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 68-108 of the vulnerable file.

			     (((l) & 0x00ff0000) >> 8)  | \
			     (((l) & 0x0000ff00) << 8)  | \
			     (((l) & 0x000000ff) << 24))  : (l))

#define rfbClientSwap64IfLE(l) \
    (*(char *)&client->endianTest ? ((((l) >> 56 ) & 0x00000000000000ffULL) | \
			     (((l) & 0x00ff000000000000ULL) >> 40)  | \
			     (((l) & 0x0000ff0000000000ULL) >> 24)  | \
			     (((l) & 0x000000ff00000000ULL) >> 8)  | \
			     (((l) & 0x00000000ff000000ULL) << 8)  | \
			     (((l) & 0x0000000000ff0000ULL) << 24)  | \
			     (((l) & 0x000000000000ff00ULL) << 40)  | \
			     (((l) & 0x00000000000000ffULL) << 56))  : (l))

#define FLASH_PORT_OFFSET 5400
#define LISTEN_PORT_OFFSET 5500
#define TUNNEL_PORT_OFFSET 5500
#define SERVER_PORT_OFFSET 5900

#define DEFAULT_CONNECT_TIMEOUT 60

#define DEFAULT_SSH_CMD "/usr/bin/ssh"
#define DEFAULT_TUNNEL_CMD  \
  (DEFAULT_SSH_CMD " -f -L %L:localhost:%R %H sleep 20")
#define DEFAULT_VIA_CMD     \
  (DEFAULT_SSH_CMD " -f -L %L:%H:%R %G sleep 20")

#if(defined __cplusplus)
extern "C"
{
#endif

/** vncrec */

typedef struct {
  FILE* file;
  struct timeval tv;
  rfbBool readTimestamp;
  rfbBool doNotSleep;
} rfbVNCRec;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,6 +85,7 @@
 #define SERVER_PORT_OFFSET 5900
 
 #define DEFAULT_CONNECT_TIMEOUT 60
+#define DEFAULT_READ_TIMEOUT 0
 
 #define DEFAULT_SSH_CMD "/usr/bin/ssh"
 #define DEFAULT_TUNNEL_CMD  \
@@ -454,6 +455,9 @@
 #endif
 	/* timeout in seconds for select() after connect() */
 	unsigned int connectTimeout;
+	/* timeout in seconds when reading from half-open connections in
+	 * ReadFromRFBServer() - keep at 0 to disable timeout detection and handling */
+	unsigned int readTimeout;
 } rfbClient;
 
 /* cursor.c */
```
