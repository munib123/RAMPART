# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1647_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1647_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 2678-2718 of the vulnerable file.

 * See also: $g_upload_project_file_threshold, $g_allow_file_upload,
 *			$g_allow_reporter_upload
 * @global integer $g_upload_bug_file_threshold
 */
$g_upload_bug_file_threshold = REPORTER;

/**
 * Add bugnote threshold
 * @global integer $g_add_bugnote_threshold
 */
$g_add_bugnote_threshold = REPORTER;

/**
 * Threshold at which a user can edit the bugnotes of other users
 * @global integer $g_update_bugnote_threshold
 */
$g_update_bugnote_threshold = DEVELOPER;

/**
 * Threshold needed to view project documentation
 * @global integer $g_view_proj_doc_threshold
 */
$g_view_proj_doc_threshold = ANYBODY;

/**
 * Site manager
 * @global integer $g_manage_site_threshold
 */
$g_manage_site_threshold = MANAGER;

/**
 * Threshold at which a user is considered to be a site administrator.
 * These users have "superuser" access to all aspects of MantisBT including
 * the admin/ directory. WARNING: DO NOT CHANGE THIS VALUE UNLESS YOU
 * ABSOLUTELY KNOW WHAT YOU'RE DOING! Users at this access level have the
 * ability to damage your MantisBT installation and data within the database.
 * It is strongly advised you leave this option alone.
 * @global integer $g_admin_site_threshold
 */
$g_admin_site_threshold = ADMINISTRATOR;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2695,9 +2695,13 @@
 
 /**
  * Threshold needed to view project documentation
+ * Note: setting this to ANYBODY will let any user download attachments
+ * from private projects, regardless of their being a member of it.
+ * @see $g_enable_project_documentation
+ * @see $g_upload_project_file_threshold
  * @global integer $g_view_proj_doc_threshold
  */
-$g_view_proj_doc_threshold = ANYBODY;
+$g_view_proj_doc_threshold = VIEWER;
 
 /**
  * Site manager
```
