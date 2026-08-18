# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2802_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2802_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 50-72 of the vulnerable file.

#define NAUTILUS_METADATA_KEY_WINDOW_GEOMETRY			"nautilus-window-geometry"
#define NAUTILUS_METADATA_KEY_WINDOW_SCROLL_POSITION		"nautilus-window-scroll-position"
#define NAUTILUS_METADATA_KEY_WINDOW_SHOW_HIDDEN_FILES		"nautilus-window-show-hidden-files"
#define NAUTILUS_METADATA_KEY_WINDOW_MAXIMIZED			"nautilus-window-maximized"
#define NAUTILUS_METADATA_KEY_WINDOW_STICKY			"nautilus-window-sticky"
#define NAUTILUS_METADATA_KEY_WINDOW_KEEP_ABOVE			"nautilus-window-keep-above"

#define NAUTILUS_METADATA_KEY_SIDEBAR_BACKGROUND_COLOR   	"nautilus-sidebar-background-color"
#define NAUTILUS_METADATA_KEY_SIDEBAR_BACKGROUND_IMAGE   	"nautilus-sidebar-background-image"
#define NAUTILUS_METADATA_KEY_SIDEBAR_BUTTONS			"nautilus-sidebar-buttons"

#define NAUTILUS_METADATA_KEY_ICON_POSITION              	"nautilus-icon-position"
#define NAUTILUS_METADATA_KEY_ICON_POSITION_TIMESTAMP		"nautilus-icon-position-timestamp"
#define NAUTILUS_METADATA_KEY_ANNOTATION                 	"annotation"
#define NAUTILUS_METADATA_KEY_ICON_SCALE                 	"icon-scale"
#define NAUTILUS_METADATA_KEY_CUSTOM_ICON                	"custom-icon"
#define NAUTILUS_METADATA_KEY_CUSTOM_ICON_NAME                	"custom-icon-name"
#define NAUTILUS_METADATA_KEY_SCREEN				"screen"
#define NAUTILUS_METADATA_KEY_EMBLEMS				"emblems"

guint nautilus_metadata_get_id (const char *metadata);

#endif /* NAUTILUS_METADATA_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,6 +67,8 @@
 #define NAUTILUS_METADATA_KEY_SCREEN				"screen"
 #define NAUTILUS_METADATA_KEY_EMBLEMS				"emblems"
 
+#define NAUTILUS_METADATA_KEY_DESKTOP_FILE_TRUSTED				"trusted"
+
 guint nautilus_metadata_get_id (const char *metadata);
 
 #endif /* NAUTILUS_METADATA_H */
```
