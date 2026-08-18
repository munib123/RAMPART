# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 493_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `493_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 93-133 of the vulnerable file.

        $interbreadcrumb[] = ['url' => '#', 'name' => get_lang('Popular')];
    }
} else {
    $interbreadcrumb[] = ['url' => 'groups.php', 'name' => get_lang('Groups')];
    if (!isset($_GET['id'])) {
        $interbreadcrumb[] = ['url' => '#', 'name' => get_lang('GroupList')];
    } else {
        //$interbreadcrumb[]= array ('url' =>'#','name' => get_lang('Group'));
    }
}

// getting group information
$group_id = isset($_GET['id']) ? intval($_GET['id']) : null;
$relation_group_title = '';
$role = 0;

$usergroup = new UserGroup();

if ($group_id != 0) {
    $group_info = $usergroup->get($group_id);

    $interbreadcrumb[] = ['url' => '#', 'name' => $group_info['name']];

    if (isset($_GET['action']) && $_GET['action'] == 'leave') {
        $user_leaved = intval($_GET['u']);
        // I can "leave me myself"
        if (api_get_user_id() == $user_leaved) {
            if (UserGroup::canLeave($group_info)) {
                $usergroup->delete_user_rel_group($user_leaved, $group_id);
                Display::addFlash(
                    Display::return_message(get_lang('UserIsNotSubscribedToThisGroup'), 'confirmation', false)
                );
            }
        }
    }

    // add a user to a group if its open
    if (isset($_GET['action']) && $_GET['action'] == 'join') {
        // we add a user only if is a open group
        $user_join = intval($_GET['u']);
        if (api_get_user_id() == $user_join && !empty($group_id)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,6 +110,8 @@
 
 if ($group_id != 0) {
     $group_info = $usergroup->get($group_id);
+    $group_info['name'] = Security::remove_XSS($group_info['name']);
+    $group_info['description'] = Security::remove_XSS($group_info['description']);
 
     $interbreadcrumb[] = ['url' => '#', 'name' => $group_info['name']];
 
@@ -154,6 +156,8 @@
 $socialForum = '';
 
 $group_info = $usergroup->get($group_id);
+$group_info['name'] = Security::remove_XSS($group_info['name']);
+$group_info['description'] = Security::remove_XSS($group_info['description']);
 
 //Loading group information
 if (isset($_GET['status']) && $_GET['status'] == 'sent') {
```
