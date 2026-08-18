# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1978_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1978_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-35 of the vulnerable file.

<?php

/* For licensing terms, see /license.txt */

require_once __DIR__.'/../inc/global.inc.php';

$action = isset($_GET['action']) ? Security::remove_XSS($_GET['action']) : 'calendar_list';

$logInfo = [
    'tool' => TOOL_CALENDAR_EVENT,
    'action' => $action,
];
Event::registerLog($logInfo);

$type = isset($_REQUEST['type']) ? $_REQUEST['type'] : null;

$interbreadcrumb[] = [
    'url' => api_get_path(WEB_CODE_PATH).'calendar/agenda_js.php?type='.Security::remove_XSS($type),
    'name' => get_lang('Agenda'),
];

$currentCourseId = api_get_course_int_id();
$groupId = api_get_group_id();

if (!empty($groupId)) {
    $groupProperties = GroupManager::get_group_properties($groupId);
    $groupId = $groupProperties['iid'];
    $interbreadcrumb[] = [
        'url' => api_get_path(WEB_CODE_PATH)."group/group.php?".api_get_cidreq(),
        'name' => get_lang('Groups'),
    ];
    $interbreadcrumb[] = [
        'url' => api_get_path(WEB_CODE_PATH)."group/group_space.php?".api_get_cidreq(),
        'name' => get_lang('GroupSpace').' '.$groupProperties['name'],
    ];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,8 @@
 ];
 Event::registerLog($logInfo);
 
-$type = isset($_REQUEST['type']) ? $_REQUEST['type'] : null;
+$typeList = ['personal', 'course', 'admin', 'platform'];
+$type = isset($_REQUEST['type']) && in_array($_REQUEST['type'], $typeList, true) ? $_REQUEST['type'] : null;
 
 $interbreadcrumb[] = [
     'url' => api_get_path(WEB_CODE_PATH).'calendar/agenda_js.php?type='.Security::remove_XSS($type),
```
