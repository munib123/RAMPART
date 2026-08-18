# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2802_5
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2802_5`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.


#include "nautilus-window-slot.h"
#include "nautilus-application.h"

#include <eel/eel-glib-extensions.h>
#include <eel/eel-stock-dialogs.h>
#include <eel/eel-string.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <glib/gstdio.h>
#include <string.h>
#include <gdk/gdkx.h>

#include "nautilus-file-attributes.h"
#include "nautilus-file.h"
#include "nautilus-file-operations.h"
#include "nautilus-metadata.h"
#include "nautilus-program-choosing.h"
#include "nautilus-global-preferences.h"
#include "nautilus-signaller.h"

#define DEBUG_FLAG NAUTILUS_DEBUG_MIME
#include "nautilus-debug.h"

typedef enum
{
    ACTIVATION_ACTION_LAUNCH_DESKTOP_FILE,
    ACTIVATION_ACTION_ASK,
    ACTIVATION_ACTION_LAUNCH,
    ACTIVATION_ACTION_LAUNCH_IN_TERMINAL,
    ACTIVATION_ACTION_OPEN_IN_VIEW,
    ACTIVATION_ACTION_OPEN_IN_APPLICATION,
    ACTIVATION_ACTION_EXTRACT,
    ACTIVATION_ACTION_DO_NOTHING,
} ActivationAction;

typedef struct
{
    NautilusFile *file;
    char *uri;
} LaunchLocation;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,6 +42,7 @@
 #include "nautilus-program-choosing.h"
 #include "nautilus-global-preferences.h"
 #include "nautilus-signaller.h"
+#include "nautilus-metadata.h"
 
 #define DEBUG_FLAG NAUTILUS_DEBUG_MIME
 #include "nautilus-debug.h"
@@ -221,7 +222,6 @@
 #define RESPONSE_RUN 1000
 #define RESPONSE_DISPLAY 1001
 #define RESPONSE_RUN_IN_TERMINAL 1002
-#define RESPONSE_MARK_TRUSTED 1003
 
 #define SILENT_WINDOW_OPEN_LIMIT 5
 #define SILENT_OPEN_LIMIT 5
@@ -1517,24 +1517,35 @@
 
     switch (response_id)
     {
-        case RESPONSE_RUN:
-        {
+        case GTK_RESPONSE_OK:
+        {
+            file = nautilus_file_get_location (parameters->file);
+
+            /* We need to do this in order to prevent malicious desktop files
+             * with the executable bit already set.
+             * See https://bugzilla.gnome.org/show_bug.cgi?id=777991
+             */
+            nautilus_file_set_metadata (parameters->file, NAUTILUS_METADATA_KEY_DESKTOP_FILE_TRUSTED,
+                                        NULL,
+                                        "yes");
+
+            nautilus_file_mark_desktop_file_executable (file,
+                                                        parameters->parent_window,
+                                                        TRUE,
+                                                        NULL, NULL);
+
+            /* Need to force a reload of the attributes so is_trusted is marked
+             * correctly. Not sure why the general monitor doesn't fire in this
+             * case when setting the metadata
+             */
+            nautilus_file_invalidate_all_attributes (parameters->file);
+
             screen = gtk_widget_get_screen (GTK_WIDGET (parameters->parent_window));
             uri = nautilus_file_get_uri (parameters->file);
             DEBUG ("Launching untrusted launcher %s", uri);
             nautilus_launch_desktop_file (screen, uri, NULL,
                                           parameters->parent_window);
             g_free (uri);
-        }
-        break;
-
-        case RESPONSE_MARK_TRUSTED:
-        {
-            file = nautilus_file_get_location (parameters->file);
-            nautilus_file_mark_desktop_file_trusted (file,
-                                                     parameters->parent_window,
-                                                     TRUE,
-                                                     NULL, NULL);
             g_object_unref (file);
         }
         break;
@@ -1590,17 +1601,16 @@
                       "text", primary,
                       "secondary-text", secondary,
                       NULL);
-        gtk_dialog_add_button (GTK_DIALOG (dialog),
-                               _("_Launch Anyway"), RESPONSE_RUN);
-        if (nautilus_file_can_set_permissions (file))
-        {
-            gtk_dialog_add_button (GTK_DIALOG (dialog),
-                                   _("Mark as _Trusted"), RESPONSE_MARK_TRUSTED);
-        }
+
         gtk_dialog_add_button (GTK_DIALOG (dialog),
                                _("_Cancel"), GTK_RESPONSE_CANCEL);
+
         gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_CANCEL);
-
+        if (nautilus_file_can_set_permissions (file))
+        {
+            gtk_dialog_add_button (GTK_DIALOG (dialog),
+                                   _("Trust and _Launch"), GTK_RESPONSE_OK);
+        }
         g_signal_connect (dialog, "response",
                           G_CALLBACK (untrusted_launcher_response_callback),
                           parameters_desktop);
```
