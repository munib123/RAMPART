# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3470_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3470_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1285-1325 of the vulnerable file.

	}
	if (plugin->browser_toplevel == NULL) {
	  GdkNativeWindow netscape_xid = None;
	  NPError error = g_NPN_GetValue_real(instance, variable, &netscape_xid);
	  if (error != NPERR_NO_ERROR)
		return error;
	  if (netscape_xid == None)
		return NPERR_GENERIC_ERROR;
	  plugin->browser_toplevel = gdk_window_foreign_new(netscape_xid);
	  if (plugin->browser_toplevel == NULL)
		return NPERR_GENERIC_ERROR;
	}
	*((GdkNativeWindow *)value) = GDK_WINDOW_XWINDOW(plugin->browser_toplevel);
	break;
#if ALLOW_WINDOWLESS_PLUGINS
  case NPNVSupportsWindowless:
#endif
  case NPNVSupportsXEmbedBool:
  case NPNVWindowNPObject:
  case NPNVPluginElementNPObject:
	return g_NPN_GetValue_real(instance, variable, value);
  default:
	switch (variable & 0xff) {
	case 13: /* NPNVToolkit */
	  if (NPW_TOOLKIT == NPNVGtk2) {
		// Gtk2 does not need to depend on a specific C++ ABI
		*(NPNToolkitType *)value = NPW_TOOLKIT;
		return NPERR_NO_ERROR;
	  }
	  break;
	}
	D(bug("WARNING: unhandled variable %d (%s) in NPN_GetValue()\n", variable, string_of_NPNVariable(variable)));
	return NPERR_INVALID_PARAM;
  }

  return NPERR_NO_ERROR;
}

// Invalidates specified drawing area prior to repainting or refreshing a windowless plug-in
static void
invoke_NPN_InvalidateRect(PluginInstance *plugin, NPRect *invalidRect)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1302,6 +1302,8 @@
   case NPNVSupportsXEmbedBool:
   case NPNVWindowNPObject:
   case NPNVPluginElementNPObject:
+  case NPNVprivateModeBool:
+  case NPNVsupportsAdvancedKeyHandling:
 	return g_NPN_GetValue_real(instance, variable, value);
   default:
 	switch (variable & 0xff) {
```
