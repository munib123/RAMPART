# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 108_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `108_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 38-57 of the vulnerable file.

		}
		for (var i=0; i < aa.elements.length; i++) {
			aa.elements[i].checked = checked;
		}
}

function checksearch(e) {
	if(window.event)
		var keyCode=window.event.keyCode;
	else
		var keyCode=e.which;
	if(keyCode==13) {
		var searchfor=$('#newsearch input[name=searchfor]').val();
			if(searchfor=="") {
				newsearch.searchfor.focus();
			} else {
				$('#newsearch').trigger('submit', true);
			}
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,3 +55,12 @@
 			}
 	}
 }
+
+function alphanumeric(inputtxt) { 
+	var letters = /^[0-9a-zA-Z]+$/;
+		if (letters.test(inputtxt)) {
+			return true;
+		} else {
+			return false;
+		}
+}
```
