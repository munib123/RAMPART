# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2802_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2802_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 218-261 of the vulnerable file.

#define NSEC_PER_MICROSEC 1000
#define PROGRESS_NOTIFY_INTERVAL 100 * NSEC_PER_MICROSEC

#define MAXIMUM_DISPLAYED_FILE_NAME_LENGTH 50

#define IS_IO_ERROR(__error, KIND) (((__error)->domain == G_IO_ERROR && (__error)->code == G_IO_ERROR_ ## KIND))

#define CANCEL _("_Cancel")
#define SKIP _("_Skip")
#define SKIP_ALL _("S_kip All")
#define RETRY _("_Retry")
#define DELETE _("_Delete")
#define DELETE_ALL _("Delete _All")
#define REPLACE _("_Replace")
#define REPLACE_ALL _("Replace _All")
#define MERGE _("_Merge")
#define MERGE_ALL _("Merge _All")
#define COPY_FORCE _("Copy _Anyway")

static void
mark_desktop_file_trusted (CommonJob    *common,
                           GCancellable *cancellable,
                           GFile        *file,
                           gboolean      interactive);

static gboolean
is_all_button_text (const char *button_text)
{
    g_assert (button_text != NULL);

    return !strcmp (button_text, SKIP_ALL) ||
           !strcmp (button_text, REPLACE_ALL) ||
           !strcmp (button_text, DELETE_ALL) ||
           !strcmp (button_text, MERGE_ALL);
}

static void scan_sources (GList      *files,
                          SourceInfo *source_info,
                          CommonJob  *job,
                          OpKind      kind);


static void empty_trash_thread_func (GTask        *task,
                                     gpointer      source_object,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -235,10 +235,10 @@
 #define COPY_FORCE _("Copy _Anyway")
 
 static void
-mark_desktop_file_trusted (CommonJob    *common,
-                           GCancellable *cancellable,
-                           GFile        *file,
-                           gboolean      interactive);
+mark_desktop_file_executable (CommonJob    *common,
+                              GCancellable *cancellable,
+                              GFile        *file,
+                              gboolean      interactive);
 
 static gboolean
 is_all_button_text (const char *button_text)
@@ -5290,10 +5290,10 @@
             g_file_equal (copy_job->desktop_location, dest_dir) &&
             is_trusted_desktop_file (src, job->cancellable))
         {
-            mark_desktop_file_trusted (job,
-                                       job->cancellable,
-                                       dest,
-                                       FALSE);
+            mark_desktop_file_executable (job,
+                                          job->cancellable,
+                                          dest,
+                                          FALSE);
         }
 
         if (job->undo_info != NULL)
@@ -7887,9 +7887,9 @@
 }
 
 static void
-mark_trusted_task_done (GObject      *source_object,
-                        GAsyncResult *res,
-                        gpointer      user_data)
+mark_desktop_file_executable_task_done (GObject      *source_object,
+                                        GAsyncResult *res,
+                                        gpointer      user_data)
 {
     MarkTrustedJob *job = user_data;
 
@@ -7907,24 +7907,27 @@
 #define TRUSTED_SHEBANG "#!/usr/bin/env xdg-open\n"
 
 static void
-mark_desktop_file_trusted (CommonJob    *common,
-                           GCancellable *cancellable,
-                           GFile        *file,
-                           gboolean      interactive)
-{
-    char *contents, *new_contents;
-    gsize length, new_length;
+mark_desktop_file_executable (CommonJob    *common,
+                              GCancellable *cancellable,
+                              GFile        *file,
+                              gboolean      interactive)
+{
     GError *error;
     guint32 current_perms, new_perms;
     int response;
     GFileInfo *info;
 
 retry:
+
     error = NULL;
-    if (!g_file_load_contents (file,
-                               cancellable,
-                               &contents, &length,
-                               NULL, &error))
+    info = g_file_query_info (file,
+                              G_FILE_ATTRIBUTE_STANDARD_TYPE ","
+                              G_FILE_ATTRIBUTE_UNIX_MODE,
+                              G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
+                              common->cancellable,
+                              &error);
+
+    if (info == NULL)
     {
         if (interactive)
         {
@@ -7941,7 +7944,6 @@
             response = 0;
         }
 
-
         if (response == 0 || response == GTK_RESPONSE_DELETE_EVENT)
         {
             abort_job (common);
@@ -7958,24 +7960,18 @@
         goto out;
     }
 
-    if (!g_str_has_prefix (contents, "#!"))
-    {
-        new_length = length + strlen (TRUSTED_SHEBANG);
-        new_contents = g_malloc (new_length);
-
-        strcpy (new_contents, TRUSTED_SHEBANG);
-        memcpy (new_contents + strlen (TRUSTED_SHEBANG),
-                contents, length);
-
-        if (!g_file_replace_contents (file,
-                                      new_contents,
-                                      new_length,
-                                      NULL,
-                                      FALSE, 0,
-                                      NULL, cancellable, &error))
-        {
-            g_free (contents);
-            g_free (new_contents);
+
+    if (g_file_info_has_attribute (info, G_FILE_ATTRIBUTE_UNIX_MODE))
+    {
+        current_perms = g_file_info_get_attribute_uint32 (info, G_FILE_ATTRIBUTE_UNIX_MODE);
+        new_perms = current_perms | S_IXGRP | S_IXUSR | S_IXOTH;
+
+        if ((current_perms != new_perms) &&
+            !g_file_set_attribute_uint32 (file, G_FILE_ATTRIBUTE_UNIX_MODE,
+                                          new_perms, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
+                                          common->cancellable, &error))
+        {
+            g_object_unref (info);
 
             if (interactive)
             {
@@ -8007,93 +8003,6 @@
 
             goto out;
         }
-        g_free (new_contents);
-    }
-    g_free (contents);
-
-    info = g_file_query_info (file,
-                              G_FILE_ATTRIBUTE_STANDARD_TYPE ","
-                              G_FILE_ATTRIBUTE_UNIX_MODE,
-                              G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
-                              common->cancellable,
-                              &error);
-
-    if (info == NULL)
-    {
-        if (interactive)
-        {
-            response = run_error (common,
-                                  g_strdup (_("Unable to mark launcher trusted (executable)")),
-                                  error->message,
-                                  NULL,
-                                  FALSE,
-                                  CANCEL, RETRY,
-                                  NULL);
-        }
-        else
-        {
-            response = 0;
-        }
-
-        if (response == 0 || response == GTK_RESPONSE_DELETE_EVENT)
-        {
-            abort_job (common);
-        }
-        else if (response == 1)
-        {
-            goto retry;
-        }
-        else
-        {
-            g_assert_not_reached ();
-        }
-
-        goto out;
-    }
-
-
-    if (g_file_info_has_attribute (info, G_FILE_ATTRIBUTE_UNIX_MODE))
-    {
-        current_perms = g_file_info_get_attribute_uint32 (info, G_FILE_ATTRIBUTE_UNIX_MODE);
-        new_perms = current_perms | S_IXGRP | S_IXUSR | S_IXOTH;
-
-        if ((current_perms != new_perms) &&
-            !g_file_set_attribute_uint32 (file, G_FILE_ATTRIBUTE_UNIX_MODE,
-                                          new_perms, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
-                                          common->cancellable, &error))
-        {
-            g_object_unref (info);
-
-            if (interactive)
-            {
-                response = run_error (common,
-                                      g_strdup (_("Unable to mark launcher trusted (executable)")),
-                                      error->message,
-                                      NULL,
-                                      FALSE,
-                                      CANCEL, RETRY,
-                                      NULL);
-            }
-            else
-            {
-                response = 0;
-            }
-
-            if (response == 0 || response == GTK_RESPONSE_DELETE_EVENT)
-            {
-                abort_job (common);
-            }
-            else if (response == 1)
-            {
-                goto retry;
-            }
-            else
-            {
-                g_assert_not_reached ();
-            }
-
-            goto out;
-        }
     }
     g_object_unref (info);
 out:
@@ -8101,10 +8010,10 @@
 }
 
 static void
-mark_trusted_task_thread_func (GTask        *task,
-                               gpointer      source_object,
-                               gpointer      task_data,
-                               GCancellable *cancellable)
+mark_desktop_file_executable_task_thread_func (GTask        *task,
+                                               gpointer      source_object,
+                                               gpointer      task_data,
+                                               GCancellable *cancellable)
 {
     MarkTrustedJob *job = task_data;
     CommonJob *common;
@@ -8113,18 +8022,18 @@
 
     nautilus_progress_info_start (job->common.progress);
 
... (diff truncated)
```
