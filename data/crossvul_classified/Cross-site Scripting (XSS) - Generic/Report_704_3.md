# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 704_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `704_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 104-144 of the vulnerable file.

        if (link_attach) {
            $(link_attach).css("display", "none");
        }
    }
}
</script>';

$htmlHeadXtra[] = '<style>
.attachment-link {
    margin: 12px;
}
#link-more-attach {
    color: white;
    cursor: pointer;
    width: 120px;
}
</style>';

$ticket_id = (int) $_REQUEST['ticket_id'];
$ticket = TicketManager::get_ticket_detail_by_id($ticket_id);
if (!isset($ticket['ticket'])) {
    api_not_allowed(true);
}
if (!isset($_REQUEST['ticket_id'])) {
    header('Location: '.api_get_path(WEB_CODE_PATH).'ticket/tickets.php');
    exit;
}

/*if (isset($_POST['response'])) {
    if ($user_id == $ticket['ticket']['assigned_last_user'] || api_is_platform_admin()) {
        $response = $_POST['response'] === '1' ? true : false;
        $newStatus = TicketManager::STATUS_PENDING;
        if ($response) {
            $newStatus = TicketManager::STATUS_CLOSE;
        }
        TicketManager::update_ticket_status(
            TicketManager::getStatusIdFromCode($newStatus),
            $ticket_id,
            $user_id
        );
        Display::addFlash(Display::return_message(get_lang('Updated')));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,7 +121,12 @@
 
 $ticket_id = (int) $_REQUEST['ticket_id'];
 $ticket = TicketManager::get_ticket_detail_by_id($ticket_id);
-if (!isset($ticket['ticket'])) {
+if (!isset($ticket['ticket']) ||
+    // make sure it's either a user assigned to this ticket, or the reporter, or and admin
+    !($ticket['ticket']['assigned_last_user'] == $user_id ||
+      $ticket['ticket']['sys_insert_user_id'] == $user_id ||
+      $isAdmin)
+    ) {
     api_not_allowed(true);
 }
 if (!isset($_REQUEST['ticket_id'])) {
@@ -347,11 +352,12 @@
 }
 $senderData = get_lang('AddedBy').' '.$ticket['usuario']['complete_name_with_message_link'];
 
+
 echo '<table width="100%" >
         <tr>
           <td colspan="3">
           <h1>'.$title.'</h1>
-          <h2>'.$ticket['ticket']['subject'].'</h2>
+          <h2>'.Security::remove_XSS($ticket['ticket']['subject']).'</h2>
           <p>
             '.$senderData.' '.
             get_lang('Created').' '.
@@ -405,11 +411,12 @@
             <td colspan="2"></td>
           </tr>';
 }
+
 echo '<tr>
         <td>
         <hr />
         <b>'.get_lang('Description').':</b> <br />
-        '.$ticket['ticket']['message'].'
+        '.Security::remove_XSS($ticket['ticket']['message']).'
         <hr />
         </td>            
      </tr>
```
