# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4024_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4024_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 19-59 of the vulnerable file.

        $title = $RET[1]['TITLE'];
        $calendar_id = $RET[1]['CALENDAR_ID'];
    } else {
        $_REQUEST['event_id'] = 'new';
        $title = 'New Event';
        $RET[1]['SCHOOL_DATE'] = date('Y-m-d', strtotime($_REQUEST['school_date']));
        $RET[1]['CALENDAR_ID'] = '';
        $calendar_id = $_REQUEST['calendar_id'];
    }
    echo "<FORM name=popform class=\"m-b-0\" id=popform action=Modules.php?modname=schoolsetup/Calendar.php&dd=$_REQUEST[school_date]&modfunc=detail&event_id=$_REQUEST[event_id]&calendar_id=$calendar_id&month=$_REQUEST[month]&year=$_REQUEST[year] METHOD=POST>";
} else {
    $RET = DBGet(DBQuery('SELECT TITLE,STAFF_ID,DATE_FORMAT(DUE_DATE,\'%d-%b-%y\') AS SCHOOL_DATE,ASSIGNED_DATE,DUE_DATE,DESCRIPTION FROM gradebook_assignments WHERE ASSIGNMENT_ID=\'' . $_REQUEST[assignment_id] . '\''));
    $title = $RET[1]['TITLE'];
    $RET[1]['STAFF_ID'] = GetTeacher($RET[1]['STAFF_ID']);
}

echo '<div class="modal-body">';

echo '<div id=err_message ></div>';


if ($RET[1]['TITLE'] == '') {
    echo '<div class="form-group">';
    echo '<label class="control-label">Title : &nbsp;</label>';
    echo (User('PROFILE') == 'admin' ? TextInputModal($RET[1]['TITLE'], 'values[TITLE]', '', 'id=title placeholder="Enter Title"') : $RET[1]['TITLE']);
    echo '</div>';
} else {
    echo '<div class="form-group">';
    echo '<label class="control-label">Title : &nbsp;</label>';
    //echo (User('PROFILE') == 'admin' ? TextInputCusIdModal($RET[1]['TITLE'], 'values[TITLE]', '', ' placeholder="Enter Title"', true, 'title') : $RET[1]['TITLE']);
    echo (User('PROFILE') == 'admin' ? '<input class="form-control" id="values[TITLE]" name="values[TITLE]" value="' . $RET[1]['TITLE'] . '" placeholder="Enter Title" size="10" type="text">' : $RET[1]['TITLE']);
    echo '</div>';
}

if ($RET[1]['STAFF_ID']) {
    echo '<div class="form-group"><label class="control-label">Teacher : &nbsp;</label>' . (User('PROFILE') == 'admin' ? TextAreaInput($RET[1]['STAFF_ID'], 'values[STAFF_ID]', '', 'placeholder="Enter Teacher"') : $RET[1]['STAFF_ID']) . '</div>';
}

if ($RET[1]['ASSIGNED_DATE']) {
    echo '<div class="form-group"><label class="control-label">Assigned Date : &nbsp;</label>' . (User('PROFILE') == 'admin' ? TextAreaInput($RET[1]['ASSIGNED_DATE'], 'values[ASSIGNED_DATE]', '', 'placeholder="Enter Assigned Date"') : $RET[1]['ASSIGNED_DATE']) . '</div>';
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,9 @@
 
 echo '<div id=err_message ></div>';
 
+echo '<div class="form-group">';
+echo '<label class="control-label">Date : '.$_REQUEST['school_date'].'&nbsp;</label>';
+echo '</div>';
 
 if ($RET[1]['TITLE'] == '') {
     echo '<div class="form-group">';
```
