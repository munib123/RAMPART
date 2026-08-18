# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 108_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `108_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 1-31 of the vulnerable file.

function checkusername() {
	var username=$('#newuser input[name=user]').val();
	var password=$('#newuser input[name=password]').val();
		if(username=="" || password=="") {
			toastr.error('You must enter a username and a password');
				if(username=="") {
					newuser.user.focus();
				} else if(password=="") {
					newuser.password.focus();
				}
		} else {
			jQuery.ajax({
				type: 'post',
				url: 'functions/ajaxhelper.php',
				data: 'function=1&username='+username,
				cache: false,
				success: function(response) {
					if(response==1) {
						toastr.error('Username already exists');
						newuser.user.focus();
					} else {
						$('#newuser').trigger('submit', true);
					}
				}
			});
		}
}

function checkeditusername() {
	var username=$('#edituser input[name=user]').val();
	var rusername=$('#edituser input[name=ruser]').val();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,14 @@
 				} else if(password=="") {
 					newuser.password.focus();
 				}
+		} else if(alphanumeric(username)==false || alphanumeric(password)==false) {
+			if(alphanumeric(username)==false) {
+				toastr.error('Username contains invalid characters');
+				newuser.user.focus();
+			} else if(alphanumeric(password)==false) {
+				toastr.error('Password contains invalid characters');
+				newuser.password.focus();
+			}
 		} else {
 			jQuery.ajax({
 				type: 'post',
@@ -38,6 +46,14 @@
 				if(username=="") {
 					edituser.user.focus();
 				}
+		} else if(alphanumeric(username)==false || alphanumeric(password)==false) {
+			if(alphanumeric(username)==false) {
+				toastr.error('Username contains invalid characters');
+				newuser.user.focus();
+			} else if(alphanumeric(password)==false) {
+				toastr.error('Password contains invalid characters');
+				newuser.password.focus();
+			}
 		} else {
 			if(username!=rusername) {
 				jQuery.ajax({
```
