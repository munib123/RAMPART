# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4711_1
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4711_1`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 163-205 of the vulnerable file.

   gtk_entry_set_max_length(GTK_ENTRY (entry1), ETH_ASCII_ADDR_LEN);
   gtk_table_attach_defaults(GTK_TABLE (table), entry1, 1, 2, 0, 1); 
   gtk_widget_show(entry1);

   label = gtk_label_new("IP Address");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach(GTK_TABLE (table), label, 0, 1, 1, 2, GTK_FILL, GTK_FILL, 0, 0);
   gtk_widget_show(label);

   entry2 = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY (entry2), IP6_ASCII_ADDR_LEN);
   gtk_table_attach_defaults(GTK_TABLE (table), entry2, 1, 2, 1, 2);
   gtk_widget_show(entry2);

   response = gtk_dialog_run(GTK_DIALOG(dialog));
   if(response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);

      snprintf(params, 6, "icmp:");

      strncat(params, gtk_entry_get_text(GTK_ENTRY(entry1)), PARAMS_LEN);
      strncat(params, "/", PARAMS_LEN);
      strncat(params, gtk_entry_get_text(GTK_ENTRY(entry2)), PARAMS_LEN);

      gtkui_start_mitm();
   }

   gtk_widget_destroy(dialog);

   /* a simpler method:
      gtkui_input_call("Parameters :", params + strlen("icmp:"), PARAMS_LEN - strlen("icmp:"), gtkui_start_mitm);
    */
}

void gtkui_port_stealing(void)
{
   GtkWidget *dialog, *vbox, *hbox, *image, *button1, *button2, *frame;
   gint response = 0;
   gboolean remote = FALSE;
   
   DEBUG_MSG("gtk_port_stealing"); 
      
   dialog = gtk_dialog_new_with_buttons("MITM Attack: Port Stealing", GTK_WINDOW (window),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -180,9 +180,9 @@
 
       snprintf(params, 6, "icmp:");
 
-      strncat(params, gtk_entry_get_text(GTK_ENTRY(entry1)), PARAMS_LEN);
-      strncat(params, "/", PARAMS_LEN);
-      strncat(params, gtk_entry_get_text(GTK_ENTRY(entry2)), PARAMS_LEN);
+      strncat(params, gtk_entry_get_text(GTK_ENTRY(entry1)), ETH_ASCII_ADDR_LEN);
+      strncat(params, "/", 1);
+      strncat(params, gtk_entry_get_text(GTK_ENTRY(entry2)), IP6_ASCII_ADDR_LEN);
 
       gtkui_start_mitm();
    }
```
