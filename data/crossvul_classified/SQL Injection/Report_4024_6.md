# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 4024_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4024_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 69-110 of the vulnerable file.

     }
     } catch (e) {
     
     error_function(e.description);
     }
     }
     
     xmlHttp.open("GET", url);
     xmlHttp.send(null);*/
}
// --------------------------------------------------- USER ----------------------------------------------------------------------------------- //

function usercheck_init(i) {
    var obj = document.getElementById('ajax_output');
    obj.innerHTML = '';

    if (i.value.length < 1)
        return;

    var err = new Array();
    if (i.value.match(/[^A-Za-z0-9_]/))
        err[err.length] = 'Username can only contain letters, numbers and underscores';
    if (i.value.length < 3)
        err[err.length] = 'Username too short';
    if (err != '') {
        obj.style.color = '#ff0000';
        obj.innerHTML = err.join('<br />');
        return;
    }

    var pqr = i.value;


    ajax_call('Validator.php?u=' + i.value + 'user', usercheck_callback, usercheck_error);
}

function usercheck_callback(data) {
    var obj = document.getElementById('ajax_output');
    if (data == 1)
        obj.style.color = '#008800';
    else
        obj.style.color = '#ff0000';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,15 +86,25 @@
         return;
 
     var err = new Array();
-    if (i.value.match(/[^A-Za-z0-9_]/))
-        err[err.length] = 'Username can only contain letters, numbers and underscores';
+    if (i.value.match(/[^A-Za-z0-9_@.]/))
+        err[err.length] = 'Username can only contain letters, numbers, underscores, at the rate and dots';
     if (i.value.length < 3)
         err[err.length] = 'Username too short';
     if (err != '') {
         obj.style.color = '#ff0000';
         obj.innerHTML = err.join('<br />');
+
+        if(i.value.length > 1)
+        {
+            window.$("#staff_username_flag").val("0");
+            window.$("#mod_staff_btn").attr("disabled", true);
+        }
+
         return;
     }
+
+    window.$("#staff_username_flag").val("1");
+    window.$("#mod_staff_btn").attr("disabled", false);
 
     var pqr = i.value;
 
@@ -112,6 +122,23 @@
         obj.innerHTML = 'Username Available';
     else
         obj.innerHTML = 'Username already taken';
+
+
+    var staff_username = document.getElementById("USERNAME").value;
+    var staff_username_flag = document.getElementById("staff_username_flag").value;
+
+    if(staff_username != '' && staff_username_flag == '0')
+    {
+        var obj = document.getElementById('ajax_output');
+        obj.style.color = '#ff0000';
+        obj.innerHTML = 'Username can only contain letters, numbers, underscores, at the rate and dots';
+
+        window.$("#mod_staff_btn").attr("disabled", true);
+    }
+    else
+    {
+        window.$("#mod_staff_btn").attr("disabled", false);
+    }
 }
 
 function usercheck_init_mod(i, opt) {
@@ -122,15 +149,25 @@
         return;
 
     var err = new Array();
-    if (i.value.match(/[^A-Za-z0-9_]/))
-        err[err.length] = 'Username can only contain letters, numbers and underscores';
+    if (i.value.match(/[^A-Za-z0-9_@.]/))
+        err[err.length] = 'Username can only contain letters, numbers, underscores, at the rate and dots';
     if (i.value.length < 3)
         err[err.length] = 'Username Too Short';
     if (err != '') {
         obj.style.color = '#ff0000';
         obj.innerHTML = err.join('<br />');
+
+        if(i.value.length > 1)
+        {
+            window.$("#staff_username_flag").val("0");
+            window.$("#mod_staff_btn").attr("disabled", true);
+        }
+
         return;
     }
+
+    window.$("#staff_username_flag").val("1");
+    window.$("#mod_staff_btn").attr("disabled", false);
 
     var pqr = i.value;
 
@@ -147,6 +184,22 @@
     var obj = document.getElementById('ajax_output_1');
     obj.style.color = (response) ? '#008800' : '#ff0000';
     obj.innerHTML = (response == 1) ? 'Username Available' : 'Username already taken';
+
+    var staff_username = document.getElementById("USERNAME").value;
+    var staff_username_flag = document.getElementById("staff_username_flag").value;
+
+    if(staff_username != '' && staff_username_flag == '0')
+    {
+        var obj = document.getElementById('ajax_output_1');
+        obj.style.color = '#ff0000';
+        obj.innerHTML = 'Username can only contain letters, numbers, underscores, at the rate and dots';
+
+        window.$("#mod_staff_btn").attr("disabled", true);
+    }
+    else
+    {
+        window.$("#mod_staff_btn").attr("disabled", false);
+    }
 }
 
 function usercheck_callback_s(data) {
@@ -155,6 +208,22 @@
     var obj = document.getElementById('ajax_output_2');
     obj.style.color = (response) ? '#008800' : '#ff0000';
     obj.innerHTML = (response == 1) ? 'Username Available' : 'Username already taken';
+
+    var staff_username = document.getElementById("USERNAME").value;
+    var staff_username_flag = document.getElementById("staff_username_flag").value;
+
+    if(staff_username != '' && staff_username_flag == '0')
+    {
+        var obj = document.getElementById('ajax_output_1');
+        obj.style.color = '#ff0000';
+        obj.innerHTML = 'Username can only contain letters, numbers, underscores, at the rate and dots';
+
+        window.$("#mod_staff_btn").attr("disabled", true);
+    }
+    else
+    {
+        window.$("#mod_staff_btn").attr("disabled", false);
+    }
 }
 
 
@@ -232,15 +301,56 @@
         return;
 
     var err = new Array();
-    if (i.value.match(/[^A-Za-z0-9_]/))
-        err[err.length] = 'Username can only contain letters, numbers and underscores';
+    if (i.value.match(/[^A-Za-z0-9_@.]/))
+        err[err.length] = 'Username can only contain letters, numbers, underscores, at the rate and dots';
     if (i.value.length < 3)
         err[err.length] = 'Username Too Short';
     if (err != '') {
         obj.style.color = '#ff0000';
         obj.innerHTML = err.join('<br />');
+
+        if(i.value.length > 1)
+        {
+            window.$("#staff_username_flag").val("0");
+            window.$("#mod_staff_btn").attr("disabled", true);
+        }
+
         return;
     }
+
+    window.$("#staff_username_flag").val("1");
+    window.$("#mod_staff_btn").attr("disabled", false);
+
+    ajax_call('Validator.php?u=' + i.value + 'stud', usercheck_callback_staff);
+}
+
+function usercheck_init_staff_2(i) {
+    var obj = document.getElementById('ajax_output_st');
+    obj.innerHTML = '';
+    document.getElementById('usr_err_check').value = '0';
+    if (i.value.length < 1)
+        return;
+
+    var err = new Array();
+    if (i.value.match(/[^A-Za-z0-9_@.]/))
+        err[err.length] = 'Username can only contain letters, numbers, underscores, at the rate and dots';
+    if (i.value.length < 3)
+        err[err.length] = 'Username Too Short';
+    if (err != '') {
+        obj.style.color = '#ff0000';
+        obj.innerHTML = err.join('<br />');
+
+        if(i.value.length > 1)
+        {
+            window.$("#staff_username_flag").val("0");
+            window.$("#mod_staff_btn").attr("disabled", true);
+        }
+
+        return;
+    }
+
+    window.$("#staff_username_flag").val("1");
+    window.$("#mod_staff_btn").attr("disabled", false);
 
     ajax_call('Validator.php?u=' + i.value + 'stud', usercheck_callback_staff);
 }
@@ -266,15 +376,24 @@
         return;
 
     var err = new Array();
-    if (i.value.match(/[^A-Za-z0-9_]/))
-        err[err.length] = 'Username can only contain letters, numbers and underscores';
+    if (i.value.match(/[^A-Za-z0-9_@.]/))
+        err[err.length] = 'Username can only contain letters, numbers, underscores, at the rate and dots';
     if (i.value.length < 3)
         err[err.length] = 'Username Too Short';
     if (err != '') {
         obj.style.color = '#ff0000';
         obj.innerHTML = err.join('<br />');
+
+        if(i.value.length > 1)
+        {
+            window.$("#stu_username_flag").val("0");
+            window.$("#mod_student_btn").attr("disabled", true);
+        }
+
         return;
     }
+    window.$("#stu_username_flag").val("1");
+    window.$("#mod_student_btn").attr("disabled", false);
     ajax_call('Validator.php?u=' + i.value + 'stud', usercheck_callback_student, usercheck_error_student);
 }
 
@@ -302,6 +421,22 @@
     {
         document.getElementById('students[USERNAME]').value = '';
         document.getElementById('students[PASSWORD]').value = '';
+    }
+
+    var student_username = document.getElementById("students[USERNAME]").value;
+    var student_username_flag = document.getElementById("stu_username_flag").value;
+
+    if(student_username != '' && student_username_flag == '0')
+    {
+        var obj = document.getElementById('ajax_output_st');
+        obj.style.color = '#ff0000';
+        obj.innerHTML = 'Username can only contain letters, numbers, underscores, at the rate and dots';
+
+        window.$("#mod_student_btn").attr("disabled", true);
+    }
+    else
+    {
+        window.$("#mod_student_btn").attr("disabled", false);
     }
 }
 
@@ -2066,8 +2201,8 @@
         return;
 
     var err = new Array();
-    if (i.value.match(/[^A-Za-z0-9_]/))
... (diff truncated)
```
