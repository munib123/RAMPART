# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 2237_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2237_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 2-42 of the vulnerable file.

/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Displays the 'User groups' sub page under 'Users' page.
 *
 * @package PhpMyAdmin
 */

require_once 'libraries/common.inc.php';
require_once 'libraries/server_users.lib.php';
require_once 'libraries/server_user_groups.lib.php';

PMA_getRelationsParam();
if (! $GLOBALS['cfgRelation']['menuswork']) {
    exit;
}

$response = PMA_Response::getInstance();
$header   = $response->getHeader();
$scripts  = $header->getScripts();
$scripts->addFile('server_user_groups.js');

$response->addHTML('<div>');
$response->addHTML(PMA_getHtmlForSubMenusOnUsersPage('server_user_groups.php'));

/**
 * Delete user group
 */
if (! empty($_REQUEST['deleteUserGroup'])) {
    PMA_deleteUserGroup($_REQUEST['userGroup']);
}

/**
 * Add a new user group
 */
if (! empty($_REQUEST['addUserGroupSubmit'])) {
    PMA_editUserGroup($_REQUEST['userGroup'], true);
}

/**
 * Update a user group
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,14 @@
 $header   = $response->getHeader();
 $scripts  = $header->getScripts();
 $scripts->addFile('server_user_groups.js');
+
+/**
+ * Only allowed to superuser 
+ */
+if (! $GLOBALS['is_superuser']) {
+    $response->addHTML(PMA_Message::error(__('No Privileges'))->getDisplay());
+    exit;
+}
 
 $response->addHTML('<div>');
 $response->addHTML(PMA_getHtmlForSubMenusOnUsersPage('server_user_groups.php'));
```
