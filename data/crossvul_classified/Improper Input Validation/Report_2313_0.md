# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2313_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2313_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 66-106 of the vulnerable file.

	/* inet check */
	if (len == S_HELLO_LEN && memcmp(data, "sorbo", 5) == 0) {
		unsigned short *id = (unsigned short*) (data+5);
		int x = 2+4+2;

		*cmd = htons(S_CMD_INET_CHECK);
		memcpy(cmd+1, addr, 4);
		memcpy(cmd+1+2, id, 2);

		printf("Inet check by %s %d\n",
		       inet_ntoa(*addr), ntohs(*id));
		if (send(s, buf, x, 0) != x)
			return 1;

		return 0;
	}

	*cmd++ = htons(S_CMD_PACKET);
	*cmd++ = *pid;
	plen = len - 2;

	last_id = ntohs(*pid);
	if (last_id > 20000)
		wrap = 1;
	if (wrap && last_id < 100) {
		wrap = 0;
		memset(ids, 0, sizeof(ids));
	}

	printf("Got packet %d %d", last_id, plen);
	if (is_dup(last_id)) {
		printf(" (DUP)\n");
		return 0;
	}
	printf("\n");

	*cmd++ = htons(plen);
	memcpy(cmd, data+2, plen);

	plen += 2 + 2 + 2;
	assert(plen <= (int) sizeof(buf));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,6 +83,8 @@
 	*cmd++ = htons(S_CMD_PACKET);
 	*cmd++ = *pid;
 	plen = len - 2;
+    if (plen < 0)
+        return 0;
 
 	last_id = ntohs(*pid);
 	if (last_id > 20000)
```
