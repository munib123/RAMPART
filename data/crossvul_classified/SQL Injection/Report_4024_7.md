# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 4024_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4024_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 647-674 of the vulnerable file.

{
    var res_length=document.getElementById('res_length').value;
    var res_len=document.getElementById('res_len').value;
    var unique_id=res_len.split(',');
//    alert(name+' '+elem.checked+' '+unique_id);
    for(var i=0;i<res_length;i++){
        if(elem.checked==true){
            if(document.getElementById(unique_id[i])){
            $('#hidden_checkboxes').append("<input type=hidden name='"+name+"["+unique_id[i]+"]' value='"+unique_id[i]+"' data-checkbox-hidden-id='"+unique_id[i]+"' />");
            document.getElementById(unique_id[i]).checked=true;
            }
        }else{
            if(document.getElementById(unique_id[i])){
            $('[data-checkbox-hidden-id='+unique_id[i]+']').remove();   
             document.getElementById(unique_id[i]).checked=false;
            }
        }
    }
}

function addseccheck_button(){
    if (document.getElementById('values[people][SECONDARY][RELATIONSHIP]').value != ''){
        document.getElementById('rss').checked=true;
    }else{
       document.getElementById('rss').checked=false; 
    }

}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -664,6 +664,31 @@
     }
 }
 
+function checkAllDtMod2(elem,name)
+{
+    var res_length=document.getElementById('res_length').value;
+    var res_len=document.getElementById('res_len').value;
+    var unique_id=res_len.split(',');
+    
+    for(var i=0;i<res_length;i++){
+        if(elem.checked==true){
+            if(document.getElementById(unique_id[i])){
+                $('#hidden_checkboxes').append("<input type=hidden name='"+name+"["+unique_id[i]+"]' value='"+unique_id[i]+"' data-checkbox-hidden-id='"+unique_id[i]+"' />");
+                // document.getElementById(unique_id[i]).checked=true;
+                // window.$('#'+unique_id[i]).attr("checked",true);
+                $(".student_label_cbx").prop('checked', true);
+                // alert(unique_id[i]);
+            }
+        }else{
+            if(document.getElementById(unique_id[i])){
+                $('[data-checkbox-hidden-id='+unique_id[i]+']').remove();   
+                // document.getElementById(unique_id[i]).checked=false;
+                $(".student_label_cbx").prop('checked', false);
+            }
+        }
+    }
+}
+
 function addseccheck_button(){
     if (document.getElementById('values[people][SECONDARY][RELATIONSHIP]').value != ''){
         document.getElementById('rss').checked=true;
```
