# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2802_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2802_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 129-168 of the vulnerable file.

					 GtkWindow            *parent_window,
					 NautilusCopyCallback  done_callback,
					 gpointer              done_callback_data);
void nautilus_file_operations_move      (GList                *files,
					 GArray               *relative_item_points,
					 GFile                *target_dir,
					 GtkWindow            *parent_window,
					 NautilusCopyCallback  done_callback,
					 gpointer              done_callback_data);
void nautilus_file_operations_duplicate (GList                *files,
					 GArray               *relative_item_points,
					 GtkWindow            *parent_window,
					 NautilusCopyCallback  done_callback,
					 gpointer              done_callback_data);
void nautilus_file_operations_link      (GList                *files,
					 GArray               *relative_item_points,
					 GFile                *target_dir,
					 GtkWindow            *parent_window,
					 NautilusCopyCallback  done_callback,
					 gpointer              done_callback_data);
void nautilus_file_mark_desktop_file_trusted (GFile           *file,
					      GtkWindow        *parent_window,
					      gboolean          interactive,
					      NautilusOpCallback done_callback,
					      gpointer          done_callback_data);
void nautilus_file_operations_extract_files (GList                   *files,
                                             GFile                   *destination_directory,
                                             GtkWindow               *parent_window,
                                             NautilusExtractCallback  done_callback,
                                             gpointer                 done_callback_data);
void nautilus_file_operations_compress (GList                  *files,
                                        GFile                  *output,
                                        AutoarFormat            format,
                                        AutoarFilter            filter,
                                        GtkWindow              *parent_window,
                                        NautilusCreateCallback  done_callback,
                                        gpointer                done_callback_data);


#endif /* NAUTILUS_FILE_OPERATIONS_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -146,11 +146,11 @@
 					 GtkWindow            *parent_window,
 					 NautilusCopyCallback  done_callback,
 					 gpointer              done_callback_data);
-void nautilus_file_mark_desktop_file_trusted (GFile           *file,
-					      GtkWindow        *parent_window,
-					      gboolean          interactive,
-					      NautilusOpCallback done_callback,
-					      gpointer          done_callback_data);
+void nautilus_file_mark_desktop_file_executable (GFile           *file,
+                                                 GtkWindow        *parent_window,
+                                                 gboolean          interactive,
+                                                 NautilusOpCallback done_callback,
+                                                 gpointer          done_callback_data);
 void nautilus_file_operations_extract_files (GList                   *files,
                                              GFile                   *destination_directory,
                                              GtkWindow               *parent_window,
```
