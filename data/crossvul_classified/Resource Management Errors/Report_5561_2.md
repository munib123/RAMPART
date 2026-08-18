# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5561_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5561_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 66-106 of the vulnerable file.


    if (client->post_notify) {
        gboolean *needed = user_data;

        *needed = TRUE;
    }
}

gboolean
cib_notify_client(gpointer key, gpointer value, gpointer user_data)
{
    const char *type = NULL;
    gboolean do_send = FALSE;

    cib_client_t *client = value;
    xmlNode *update_msg = user_data;

    CRM_CHECK(client != NULL, return TRUE);
    CRM_CHECK(update_msg != NULL, return TRUE);

    if (client->ipc == NULL) {
        crm_warn("Skipping client with NULL channel");
        return FALSE;
    }

    type = crm_element_value(update_msg, F_SUBTYPE);

    CRM_LOG_ASSERT(type != NULL);
    if (client->diffs && safe_str_eq(type, T_CIB_DIFF_NOTIFY)) {
        do_send = TRUE;

    } else if (client->replace && safe_str_eq(type, T_CIB_REPLACE_NOTIFY)) {
        do_send = TRUE;

    } else if (client->confirmations && safe_str_eq(type, T_CIB_UPDATE_CONFIRM)) {
        do_send = TRUE;

    } else if (client->pre_notify && safe_str_eq(type, T_CIB_PRE_NOTIFY)) {
        do_send = TRUE;

    } else if (client->post_notify && safe_str_eq(type, T_CIB_POST_NOTIFY)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,7 +83,7 @@
     CRM_CHECK(client != NULL, return TRUE);
     CRM_CHECK(update_msg != NULL, return TRUE);
 
-    if (client->ipc == NULL) {
+    if (client->ipc == NULL && client->session == NULL) {
         crm_warn("Skipping client with NULL channel");
         return FALSE;
     }
```
