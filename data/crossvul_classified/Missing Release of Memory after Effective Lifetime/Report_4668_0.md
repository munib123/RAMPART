# CrossVul Fix Pair: Missing Release of Memory after Effective Lifetime in c
**Pair ID:** 4668_0
**Vulnerability Class:** Missing Release of Memory after Effective Lifetime
**CWE:** CWE-401
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4668_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Memory after Effective Lifetime - This is often triggered by improper handling of malformed data or unexpectedly interrupted sessions.

## Vulnerable Code
```c
Lines 418-458 of the vulnerable file.

bail:
	if (message)
		dbus_message_unref(message);

	if (reply)
		dbus_message_unref(reply);

	dbus_error_free(&error);

	return ret;
}

#pragma mark -


int main(int argc, char * argv[])
{
	int c;
	bool ignore_driver_version_mismatch = false;
	DBusError error;
	DBusConnection* connection;

	dbus_error_init(&error);

	srandom(time(NULL));

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"version", no_argument, 0, 'v'},
			{"ignore-mismatch", no_argument, 0, 'i'},
			{"debug", no_argument, 0, 'd'},
			{"interface", required_argument, 0, 'I'},
			{"file", required_argument, 0, 'f'},
			{0, 0, 0, 0}
		};

		int option_index = 0;

		if ((optind < argc) && (find_cmd(argv[optind]) != NULL)) {
			// This is where the wpanctl command starts; skip
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -435,7 +435,7 @@
 	int c;
 	bool ignore_driver_version_mismatch = false;
 	DBusError error;
-	DBusConnection* connection;
+	DBusConnection* connection = NULL;
 
 	dbus_error_init(&error);
 
@@ -715,5 +715,11 @@
 	if (gRet == ERRORCODE_QUIT)
 		gRet = 0;
 
+	if (connection) {
+		dbus_connection_unref(connection);
+	}
+
+	dbus_error_free(&error);
+
 	return gRet;
 }
```
