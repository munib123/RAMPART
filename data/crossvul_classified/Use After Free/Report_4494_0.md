# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4494_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4494_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 569-609 of the vulnerable file.

	if (!server->capture)
	{
		WLog_ERR(TAG, "capture_new failed");
		return -1;
	}

	/* Bind magic:
	 *
	 * emtpy                 ... bind TCP all
	 * <local path>          ... bind local (IPC)
	 * bind-socket,<address> ... bind TCP to specified interface
	 */
	ipc = server->ipcSocket && (strncmp(bind_address, server->ipcSocket,
	                                    strnlen(bind_address, sizeof(bind_address))) != 0);
	if (!ipc)
	{
		size_t x, count;
		char** list = CommandLineParseCommaSeparatedValuesEx(NULL, server->ipcSocket, &count);
		if (!list || (count <= 1))
		{
			free(list);
			if (server->ipcSocket == NULL)
			{
				if (!open_port(server, NULL))
					return -1;
			}
			else
				return -1;
		}

		for (x = 1; x < count; x++)
		{
			BOOL success = open_port(server, list[x]);
			if (!success)
			{
				free(list);
				return -1;
			}
		}
		free(list);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -586,14 +586,19 @@
 		char** list = CommandLineParseCommaSeparatedValuesEx(NULL, server->ipcSocket, &count);
 		if (!list || (count <= 1))
 		{
-			free(list);
 			if (server->ipcSocket == NULL)
 			{
 				if (!open_port(server, NULL))
+				{
+					free(list);
 					return -1;
+				}
 			}
 			else
-				return -1;
+			{
+				free(list);
+				return -1;
+			}
 		}
 
 		for (x = 1; x < count; x++)
```
