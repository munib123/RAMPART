# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1674_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1674_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 416-457 of the vulnerable file.

}

static void save_text_if_changed(const char *name, const char *new_value)
{
    /* a text value can't be change if the file is not loaded */
    /* returns NULL if the name is not found; otherwise nonzero */
    if (!g_hash_table_lookup(g_loaded_texts, name))
        return;

    const char *old_value = g_cd ? problem_data_get_content_or_NULL(g_cd, name) : "";
    if (!old_value)
        old_value = "";
    if (strcmp(new_value, old_value) != 0)
    {
        struct dump_dir *dd = wizard_open_directory_for_writing(g_dump_dir_name);
        if (dd)
            dd_save_text(dd, name, new_value);

//FIXME: else: what to do with still-unsaved data in the widget??
        dd_close(dd);
        problem_data_reload_from_dump_dir();
        update_gui_state_from_problem_data(/* don't update selected event */ 0);
    }
}

static void save_text_from_text_view(GtkTextView *tv, const char *name)
{
    gchar *new_str = get_malloced_string_from_text_view(tv);
    save_text_if_changed(name, new_str);
    free(new_str);
}

static void append_to_textview(GtkTextView *tv, const char *str)
{
    GtkTextBuffer *tb = gtk_text_view_get_buffer(tv);

    /* Ensure we insert text at the end */
    GtkTextIter text_iter;
    gtk_text_buffer_get_end_iter(tb, &text_iter);
    gtk_text_buffer_place_cursor(tb, &text_iter);

    /* Deal with possible broken Unicode */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -433,8 +433,6 @@
 
 //FIXME: else: what to do with still-unsaved data in the widget??
         dd_close(dd);
-        problem_data_reload_from_dump_dir();
-        update_gui_state_from_problem_data(/* don't update selected event */ 0);
     }
 }
 
@@ -777,7 +775,11 @@
         load_text_to_text_view(GTK_TEXT_VIEW(textview), item_name);
 
         if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK)
+        {
             save_text_from_text_view(GTK_TEXT_VIEW(textview), item_name);
+            problem_data_reload_from_dump_dir();
+            update_gui_state_from_problem_data(/* don't update selected event */ 0);
+        }
 
         gtk_widget_destroy(textview);
         gtk_widget_destroy(scrolled);
@@ -2709,7 +2711,8 @@
      * these tabs will be lost */
     save_items_from_notepad();
     save_text_from_text_view(g_tv_comment, FILENAME_COMMENT);
-
+    problem_data_reload_from_dump_dir();
+    update_gui_state_from_problem_data(/* don't update selected event */ 0);
 
     if (pages[PAGENO_SUMMARY].page_widget == page)
     {
```
