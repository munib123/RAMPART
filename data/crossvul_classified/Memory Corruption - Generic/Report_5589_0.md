# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5589_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5589_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 30-52 of the vulnerable file.

/* Read all messages remaining in the ring buffer. */
#define SYSLOG_ACTION_READ_ALL       3
/* Read and clear all messages remaining in the ring buffer */
#define SYSLOG_ACTION_READ_CLEAR     4
/* Clear ring buffer. */
#define SYSLOG_ACTION_CLEAR          5
/* Disable printk's to console */
#define SYSLOG_ACTION_CONSOLE_OFF    6
/* Enable printk's to console */
#define SYSLOG_ACTION_CONSOLE_ON     7
/* Set level of messages printed to console */
#define SYSLOG_ACTION_CONSOLE_LEVEL  8
/* Return number of unread characters in the log buffer */
#define SYSLOG_ACTION_SIZE_UNREAD    9
/* Return size of the log buffer */
#define SYSLOG_ACTION_SIZE_BUFFER   10

#define SYSLOG_FROM_CALL 0
#define SYSLOG_FROM_FILE 1

int do_syslog(int type, char __user *buf, int count, bool from_file);

#endif /* _LINUX_SYSLOG_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,6 +47,12 @@
 #define SYSLOG_FROM_CALL 0
 #define SYSLOG_FROM_FILE 1
 
+/*
+ * Syslog priority (PRI) maximum length in char : '<[0-9]{1,3}>'
+ * See RFC5424 for details
+*/
+#define SYSLOG_PRI_MAX_LENGTH 5
+
 int do_syslog(int type, char __user *buf, int count, bool from_file);
 
 #endif /* _LINUX_SYSLOG_H */
```
