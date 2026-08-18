# CrossVul Fix Pair: Origin Validation Error in c
**Pair ID:** 3127_0
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3127_0`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```c
Lines 697-737 of the vulnerable file.

    }

    xmpp_stanza_t *forwarded = xmpp_stanza_get_child_by_ns(carbons, STANZA_NS_FORWARD);
    if (!forwarded) {
        log_warning("Carbon received with no forwarded element");
        return TRUE;
    }

    xmpp_stanza_t *message = xmpp_stanza_get_child_by_name(forwarded, STANZA_NAME_MESSAGE);
    if (!message) {
        log_warning("Carbon received with no message element");
        return TRUE;
    }

    char *message_txt = xmpp_message_get_body(message);
    if (!message_txt) {
        log_warning("Carbon received with no message.");
        return TRUE;
    }

    const gchar *to = xmpp_stanza_get_to(message);
    const gchar *from = xmpp_stanza_get_from(message);

    // happens when receive a carbon of a self sent message
    if (!to) to = from;

    Jid *jid_from = jid_create(from);
    Jid *jid_to = jid_create(to);
    Jid *my_jid = jid_create(connection_get_fulljid());

    // check for pgp encrypted message
    char *enc_message = NULL;
    xmpp_stanza_t *x = xmpp_stanza_get_child_by_ns(message, STANZA_NS_ENCRYPTED);
    if (x) {
        enc_message = xmpp_stanza_get_text(x);
    }

    // if we are the recipient, treat as standard incoming message
    if (g_strcmp0(my_jid->barejid, jid_to->barejid) == 0) {
        sv_ev_incoming_carbon(jid_from->barejid, jid_from->resourcepart, message_txt, enc_message);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -714,6 +714,14 @@
         return TRUE;
     }
 
+    Jid *my_jid = jid_create(connection_get_fulljid());
+    const char *const stanza_from = xmpp_stanza_get_from(stanza);
+    Jid *msg_jid = jid_create(stanza_from);
+    if (g_strcmp0(my_jid->barejid, msg_jid->barejid) != 0) {
+        log_warning("Invalid carbon received, from: %s", stanza_from);
+        return TRUE;
+    }
+
     const gchar *to = xmpp_stanza_get_to(message);
     const gchar *from = xmpp_stanza_get_from(message);
 
@@ -722,7 +730,6 @@
 
     Jid *jid_from = jid_create(from);
     Jid *jid_to = jid_create(to);
-    Jid *my_jid = jid_create(connection_get_fulljid());
 
     // check for pgp encrypted message
     char *enc_message = NULL;
```
