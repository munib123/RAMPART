# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4024_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4024_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 341-381 of the vulnerable file.

        if (!UserStudentID())
            $_SESSION['student_id'] = $RET[1]['STUDENT_ID'];
        echo "<SELECT class=\"select\" name=student_id onChange='this.form.submit();'>";
        if (count($RET)) {
            foreach ($RET as $student) {
                echo "<OPTION value=$student[STUDENT_ID]" . ((UserStudentID() == $student['STUDENT_ID']) ? ' SELECTED' : '') . ">" . $student['FULL_NAME'] . "</OPTION>";
                if (UserStudentID() == $student['STUDENT_ID'])
                    $_SESSION['UserSchool'] = $student['SCHOOL_ID'];
            }
        }
        echo "</SELECT>";

        if (!UserMP())
            $_SESSION['UserMP'] = GetCurrentMP('QTR', DBDate());
        echo '</div>';
        echo '</FORM></li>';
    }

    //===================================================================================================

    //For Marking Period
    echo "<li><div class=\"form-group\"><FORM name=head_frm id=head_frm action=Side.php?modfunc=update&btnn=$btn&nsc=$ns method=POST>
                        <INPUT type=hidden name=modcat value='' id=modcat_input>";

    $RET = DBGet(DBQuery("SELECT MARKING_PERIOD_ID,TITLE FROM school_quarters WHERE SCHOOL_ID='" . UserSchool() . "' AND SYEAR='" . UserSyear() . "' ORDER BY SORT_ORDER"));
    if (!isset($_SESSION['UserMP']))
        $_SESSION['UserMP'] = GetCurrentMP('QTR', DBDate());

    if (!$RET) {
        $RET = DBGet(DBQuery("SELECT MARKING_PERIOD_ID,TITLE FROM school_semesters WHERE SCHOOL_ID='" . UserSchool() . "' AND SYEAR='" . UserSyear() . "' ORDER BY SORT_ORDER"));
        if (!isset($_SESSION['UserMP']))
            $_SESSION['UserMP'] = GetCurrentMP('SEM', DBDate());
    }

    if (!$RET) {
        $RET = DBGet(DBQuery("SELECT MARKING_PERIOD_ID,TITLE FROM school_years WHERE SCHOOL_ID='" . UserSchool() . "' AND SYEAR='" . UserSyear() . "' ORDER BY SORT_ORDER"));
        if (!isset($_SESSION['UserMP']))
            $_SESSION['UserMP'] = GetCurrentMP('FY', DBDate());
    }

    echo "<SELECT class=\"select\" name=mp onChange='this.form.submit();'>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -358,7 +358,7 @@
 
     //===================================================================================================
 
-    //For Marking Period
+    // For Marking Period
     echo "<li><div class=\"form-group\"><FORM name=head_frm id=head_frm action=Side.php?modfunc=update&btnn=$btn&nsc=$ns method=POST>
                         <INPUT type=hidden name=modcat value='' id=modcat_input>";
 
@@ -386,10 +386,10 @@
             echo "<OPTION value=$quarter[MARKING_PERIOD_ID]" . (UserMP() == $quarter['MARKING_PERIOD_ID'] ? ' SELECTED' : '') . ">" . $quarter['TITLE'] . "</OPTION>";
     }
     echo "</SELECT>";
-    //Marking Period
+    // Marking Period
 
     echo '</FORM></div></li>';
-}##################Porfile Not Teacher End##########################################
+}################## Porfile Not Teacher End ##########################################
 
 if (UserStudentID() && User('PROFILE') != 'parent' && User('PROFILE') != 'student') {
     $RET = DBGet(DBQuery("SELECT FIRST_NAME,LAST_NAME,MIDDLE_NAME,NAME_SUFFIX FROM students WHERE STUDENT_ID='" . UserStudentID() . "'"));
@@ -458,7 +458,7 @@
             $ret_increment++;
         }
     }
-   // print_r($RET);
+   
     if (!UserCourse()) {
         $_SESSION['UserCourse'] = $RET[1]['COURSE_ID'];
     }
```
