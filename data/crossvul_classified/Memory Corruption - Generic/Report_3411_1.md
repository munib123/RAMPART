# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3411_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3411_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 165-205 of the vulnerable file.

		switch (action[0]) {
		case 's':
			// TODO handle thread selections
			if (cmd_cb (core_ptr, "ds", NULL, 0) < 0) {
				send_msg (g, "E01");
				return -1;
			}
			return send_msg (g, "OK");
		case 'c':
			// TODO handle thread selections
			if (cmd_cb (core_ptr, "dc", NULL, 0) < 0) {
				send_msg (g, "E01");
				return -1;
			}
			return send_msg (g, "OK");
		default:
			// TODO support others
			return send_msg (g, "E01");
		}
	}
}

static int _server_handle_qAttached(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
	if (send_ack (g) < 0) {
		return -1;
	}
	// TODO check if process was attached or created
	// Right now, says that process was created
	return send_msg (g, "0");
}

// TODO, proper handling of Hg and Hc (right now handled identically)

// Set thread for all operations other than "step" and "continue"
static int _server_handle_Hg(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
	// We don't yet support multiprocess. Client is not supposed to send Hgp. If we receive it anyway,
	// send error
	char cmd[32];
	int tid;
	if (send_ack (g) < 0) {
		return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -182,6 +182,7 @@
 			return send_msg (g, "E01");
 		}
 	}
+	return -1;
 }
 
 static int _server_handle_qAttached(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
```
