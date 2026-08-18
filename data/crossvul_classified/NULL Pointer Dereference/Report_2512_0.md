# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2512_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2512_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 74-114 of the vulnerable file.

}

int tcmur_register_handler(struct tcmur_handler *handler)
{
	struct tcmur_handler *h;
	int i;

	for (i = 0; i < darray_size(g_runner_handlers); i++) {
		h = darray_item(g_runner_handlers, i);
		if (!strcmp(h->subtype, handler->subtype)) {
			tcmu_err("Handler %s has already been registered\n",
				 handler->subtype);
			return -1;
		}
	}

	darray_append(g_runner_handlers, handler);
	return 0;
}

bool tcmur_unregister_handler(struct tcmur_handler *handler)
{
	int i;
	for (i = 0; i < darray_size(g_runner_handlers); i++) {
		if (darray_item(g_runner_handlers, i) == handler) {
			darray_remove(g_runner_handlers, i);
			return true;
		}
	}
	return false;
}

static int is_handler(const struct dirent *dirent)
{
	if (strncmp(dirent->d_name, "handler_", 8))
		return 0;

	return 1;
}

static int open_handlers(void)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,6 +91,12 @@
 	return 0;
 }
 
+static int tcmur_register_dbus_handler(struct tcmur_handler *handler)
+{
+	assert(handler->_is_dbus_handler == true);
+	return tcmur_register_handler(handler);
+}
+
 bool tcmur_unregister_handler(struct tcmur_handler *handler)
 {
 	int i;
@@ -101,6 +107,16 @@
 		}
 	}
 	return false;
+}
+
+static bool tcmur_unregister_dbus_handler(struct tcmur_handler *handler)
+{
+	bool ret = false;
+	assert(handler->_is_dbus_handler == true);
+
+	ret = tcmur_unregister_handler(handler);
+
+	return ret;
 }
 
 static int is_handler(const struct dirent *dirent)
@@ -315,7 +331,7 @@
 
 	if (info->register_invocation) {
 		info->connection = connection;
-		tcmur_register_handler(handler);
+		tcmur_register_dbus_handler(handler);
 		dbus_export_handler(handler, G_CALLBACK(on_dbus_check_config));
 		g_dbus_method_invocation_return_value(info->register_invocation,
 			    g_variant_new("(bs)", TRUE, "succeeded"));
@@ -340,7 +356,7 @@
 			    g_variant_new("(bs)", FALSE, reason));
 		g_free(reason);
 	}
-	tcmur_unregister_handler(handler);
+	tcmur_unregister_dbus_handler(handler);
 	dbus_unexport_handler(handler);
 }
 
@@ -366,6 +382,8 @@
 	handler->handle_cmd   = dbus_handler_handle_cmd;
 
 	info = g_new0(struct dbus_info, 1);
+	handler->opaque = info;
+	handler->_is_dbus_handler = 1;
 	info->register_invocation = invocation;
 	info->watcher_id = g_bus_watch_name(G_BUS_TYPE_SYSTEM,
 					    bus_name,
@@ -394,8 +412,16 @@
 				      "unknown subtype"));
 		return TRUE;
 	}
+	else if (handler->_is_dbus_handler != 1) {
+		g_dbus_method_invocation_return_value(invocation,
+			g_variant_new("(bs)", FALSE,
+				      "cannot unregister internal handler"));
+		return TRUE;
+	}
+
 	dbus_unexport_handler(handler);
-	tcmur_unregister_handler(handler);
+	tcmur_unregister_dbus_handler(handler);
+
 	g_bus_unwatch_name(info->watcher_id);
 	g_free(info);
 	g_free(handler);
```
