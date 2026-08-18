# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2513_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2513_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 369-409 of the vulnerable file.

	info->register_invocation = invocation;
	info->watcher_id = g_bus_watch_name(G_BUS_TYPE_SYSTEM,
					    bus_name,
					    G_BUS_NAME_WATCHER_FLAGS_NONE,
					    on_handler_appeared,
					    on_handler_vanished,
					    handler,
					    NULL);
	g_free(bus_name);
	handler->opaque = info;
	return TRUE;
}

static gboolean
on_unregister_handler(TCMUService1HandlerManager1 *interface,
		      GDBusMethodInvocation *invocation,
		      gchar *subtype,
		      gpointer user_data)
{
	struct tcmur_handler *handler = find_handler_by_subtype(subtype);
	struct dbus_info *info = handler->opaque;

	if (!handler) {
		g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(bs)", FALSE,
				      "unknown subtype"));
		return TRUE;
	}
	dbus_unexport_handler(handler);
	tcmur_unregister_handler(handler);
	g_bus_unwatch_name(info->watcher_id);
	g_free(info);
	g_free(handler);
	g_dbus_method_invocation_return_value(invocation,
		g_variant_new("(bs)", TRUE, "succeeded"));
	return TRUE;
}

void dbus_handler_manager1_init(GDBusConnection *connection)
{
	GError *error = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -386,7 +386,7 @@
 		      gpointer user_data)
 {
 	struct tcmur_handler *handler = find_handler_by_subtype(subtype);
-	struct dbus_info *info = handler->opaque;
+	struct dbus_info *info = handler ? handler->opaque : NULL;
 
 	if (!handler) {
 		g_dbus_method_invocation_return_value(invocation,
```
