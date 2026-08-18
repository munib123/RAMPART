# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5589_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5589_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 621-661 of the vulnerable file.

		*level = lev;
	return len;
}

/*
 * Call the console drivers, asking them to write out
 * log_buf[start] to log_buf[end - 1].
 * The console_lock must be held.
 */
static void call_console_drivers(unsigned start, unsigned end)
{
	unsigned cur_index, start_print;
	static int msg_level = -1;

	BUG_ON(((int)(start - end)) > 0);

	cur_index = start;
	start_print = start;
	while (cur_index != end) {
		if (msg_level < 0 && ((end - cur_index) > 2)) {
			/* strip log prefix */
			cur_index += log_prefix(&LOG_BUF(cur_index), &msg_level, NULL);
			start_print = cur_index;
		}
		while (cur_index != end) {
			char c = LOG_BUF(cur_index);

			cur_index++;
			if (c == '\n') {
				if (msg_level < 0) {
					/*
					 * printk() has already given us loglevel tags in
					 * the buffer.  This code is here in case the
					 * log buffer has wrapped right round and scribbled
					 * on those tags
					 */
					msg_level = default_message_loglevel;
				}
				_call_console_drivers(start_print, cur_index, msg_level);
				msg_level = -1;
				start_print = cur_index;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -638,8 +638,19 @@
 	start_print = start;
 	while (cur_index != end) {
 		if (msg_level < 0 && ((end - cur_index) > 2)) {
+			/*
+			 * prepare buf_prefix, as a contiguous array,
+			 * to be processed by log_prefix function
+			 */
+			char buf_prefix[SYSLOG_PRI_MAX_LENGTH+1];
+			unsigned i;
+			for (i = 0; i < ((end - cur_index)) && (i < SYSLOG_PRI_MAX_LENGTH); i++) {
+				buf_prefix[i] = LOG_BUF(cur_index + i);
+			}
+			buf_prefix[i] = '\0'; /* force '\0' as last string character */
+
 			/* strip log prefix */
-			cur_index += log_prefix(&LOG_BUF(cur_index), &msg_level, NULL);
+			cur_index += log_prefix((const char *)&buf_prefix, &msg_level, NULL);
 			start_print = cur_index;
 		}
 		while (cur_index != end) {
```
