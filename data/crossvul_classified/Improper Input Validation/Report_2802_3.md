# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2802_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2802_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 34-74 of the vulnerable file.

    NAUTILUS_METADATA_KEY_LIST_VIEW_SORT_REVERSED,
    NAUTILUS_METADATA_KEY_LIST_VIEW_VISIBLE_COLUMNS,
    NAUTILUS_METADATA_KEY_LIST_VIEW_COLUMN_ORDER,
    NAUTILUS_METADATA_KEY_WINDOW_GEOMETRY,
    NAUTILUS_METADATA_KEY_WINDOW_SCROLL_POSITION,
    NAUTILUS_METADATA_KEY_WINDOW_SHOW_HIDDEN_FILES,
    NAUTILUS_METADATA_KEY_WINDOW_MAXIMIZED,
    NAUTILUS_METADATA_KEY_WINDOW_STICKY,
    NAUTILUS_METADATA_KEY_WINDOW_KEEP_ABOVE,
    NAUTILUS_METADATA_KEY_SIDEBAR_BACKGROUND_COLOR,
    NAUTILUS_METADATA_KEY_SIDEBAR_BACKGROUND_IMAGE,
    NAUTILUS_METADATA_KEY_SIDEBAR_BUTTONS,
    NAUTILUS_METADATA_KEY_ANNOTATION,
    NAUTILUS_METADATA_KEY_ICON_POSITION,
    NAUTILUS_METADATA_KEY_ICON_POSITION_TIMESTAMP,
    NAUTILUS_METADATA_KEY_ICON_SCALE,
    NAUTILUS_METADATA_KEY_CUSTOM_ICON,
    NAUTILUS_METADATA_KEY_CUSTOM_ICON_NAME,
    NAUTILUS_METADATA_KEY_SCREEN,
    NAUTILUS_METADATA_KEY_EMBLEMS,
    NULL
};

guint
nautilus_metadata_get_id (const char *metadata)
{
    static GHashTable *hash;
    int i;

    if (hash == NULL)
    {
        hash = g_hash_table_new (g_str_hash, g_str_equal);
        for (i = 0; used_metadata_names[i] != NULL; i++)
        {
            g_hash_table_insert (hash,
                                 used_metadata_names[i],
                                 GINT_TO_POINTER (i + 1));
        }
    }

    return GPOINTER_TO_INT (g_hash_table_lookup (hash, metadata));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,6 +51,7 @@
     NAUTILUS_METADATA_KEY_CUSTOM_ICON_NAME,
     NAUTILUS_METADATA_KEY_SCREEN,
     NAUTILUS_METADATA_KEY_EMBLEMS,
+    NAUTILUS_METADATA_KEY_DESKTOP_FILE_TRUSTED,
     NULL
 };
 
```
