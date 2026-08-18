# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4047_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4047_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 55-95 of the vulnerable file.

    }

    // show images?
    rcmail_check_safe($MESSAGE);

    // set message charset as default
    if (!empty($MESSAGE->headers->charset)) {
        $RCMAIL->storage->set_charset($MESSAGE->headers->charset);
    }

    $OUTPUT->set_pagetitle(abbreviate_string($MESSAGE->subject, 128, '...', true));

    // set message environment
    $OUTPUT->set_env('uid', $msg_id);
    $OUTPUT->set_env('safemode', $MESSAGE->is_safe);
    $OUTPUT->set_env('message_context', $MESSAGE->context);
    $OUTPUT->set_env('sender', $MESSAGE->sender['string']);
    $OUTPUT->set_env('mailbox', $mbox_name);
    $OUTPUT->set_env('username', $RCMAIL->get_user_name());
    $OUTPUT->set_env('permaurl', $RCMAIL->url(array('_action' => 'show', '_uid' => $msg_id, '_mbox' => $mbox_name)));

    if ($MESSAGE->headers->get('list-post', false)) {
        $OUTPUT->set_env('list_post', true);
    }

    // set environment
    $OUTPUT->set_env('delimiter', $RCMAIL->storage->get_hierarchy_delimiter());
    $OUTPUT->set_env('mimetypes', rcmail_supported_mimetypes());

    // set configuration
    $RCMAIL->set_env_config(array('delete_junk', 'flag_for_deletion', 'read_when_deleted',
        'skip_deleted', 'display_next', 'forward_attachment'));

    // set special folders
    foreach (array('drafts', 'trash', 'junk') as $mbox) {
        if ($folder = $RCMAIL->config->get($mbox . '_mbox')) {
            $OUTPUT->set_env($mbox . '_mailbox', $folder);
        }
    }

    if ($MESSAGE->has_html_part()) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,6 +72,8 @@
     $OUTPUT->set_env('mailbox', $mbox_name);
     $OUTPUT->set_env('username', $RCMAIL->get_user_name());
     $OUTPUT->set_env('permaurl', $RCMAIL->url(array('_action' => 'show', '_uid' => $msg_id, '_mbox' => $mbox_name)));
+    $OUTPUT->set_env('delimiter', $RCMAIL->storage->get_hierarchy_delimiter());
+    $OUTPUT->set_env('mimetypes', rcmail_supported_mimetypes());
 
     if ($MESSAGE->headers->get('list-post', false)) {
         $OUTPUT->set_env('list_post', true);
```
