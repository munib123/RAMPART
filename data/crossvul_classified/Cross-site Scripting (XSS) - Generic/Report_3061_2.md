# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3061_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3061_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 804-844 of the vulnerable file.

  });

  if (unauth_nodes.length == 0) {
    if (callback_success !== null) {
      callback_success();
    }
    return;
  }

  if (unauth_nodes.length == 1) {
    dialog_obj.find("#same_pass").hide();
  } else {
    dialog_obj.find("#same_pass").show();
    dialog_obj.find("input:checkbox[name=all]").prop("checked", false);
    dialog_obj.find("#pass_for_all").val("");
    dialog_obj.find("#pass_for_all").hide();
  }

  dialog_obj.find('#auth_nodes_list').empty();
  unauth_nodes.forEach(function(node) {
    dialog_obj.find('#auth_nodes_list').append("\t\t\t<tr><td>" + node + '</td><td><input type="password" name="' + node + '-pass"></td></tr>\n');
  });

}

function add_existing_dialog() {
  var buttonOpts = [
    {
      text: "Add Existing",
      id: "add_existing_submit_btn",
      click: function () {
        $("#add_existing_cluster").find("table.err_msg_table").find("span[id$=_error_msg]").hide();
        $("#add_existing_submit_btn").button("option", "disabled", true);
        checkExistingNode();
      }
    },
    {
      text: "Cancel",
      click: function() {
        $(this).dialog("close");
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -821,7 +821,7 @@
 
   dialog_obj.find('#auth_nodes_list').empty();
   unauth_nodes.forEach(function(node) {
-    dialog_obj.find('#auth_nodes_list').append("\t\t\t<tr><td>" + node + '</td><td><input type="password" name="' + node + '-pass"></td></tr>\n');
+    dialog_obj.find('#auth_nodes_list').append("\t\t\t<tr><td>" + htmlEncode(node) + '</td><td><input type="password" name="' + htmlEncode(node) + '-pass"></td></tr>\n');
   });
 
 }
```
