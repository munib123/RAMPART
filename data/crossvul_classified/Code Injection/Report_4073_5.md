# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in javascript
**Pair ID:** 4073_5
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4073_5`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```javascript
Lines 110-151 of the vulnerable file.

    input.setAttribute("autocorrect", "off");
    input.setAttribute("autocapitalize", "off");
    input.setAttribute("spellcheck", false);
  }

  table.on("order.dt", function () {
    var order = table.order();
    if (order[0][0] !== 0 || order[0][1] !== "asc") {
      $("#resetButton").removeClass("hidden");
    } else {
      $("#resetButton").addClass("hidden");
    }
  });
  $("#resetButton").on("click", function () {
    table.order([[0, "asc"]]).draw();
    $("#resetButton").addClass("hidden");
  });
});

function addGroup() {
  var name = $("#new_name").val();
  var desc = $("#new_desc").val();

  utils.disableAll();
  utils.showAlert("info", "", "Adding group...", name);

  if (name.length === 0) {
    utils.showAlert("warning", "", "Warning", "Please specify a group name");
    return;
  }

  $.ajax({
    url: "scripts/pi-hole/php/groups.php",
    method: "post",
    dataType: "json",
    data: { action: "add_group", name: name, desc: desc, token: token },
    success: function (response) {
      utils.enableAll();
      if (response.success) {
        utils.showAlert("success", "fas fa-plus", "Successfully added group", name);
        $("#new_name").val("");
        $("#new_desc").val("");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -127,8 +127,8 @@
 });
 
 function addGroup() {
-  var name = $("#new_name").val();
-  var desc = $("#new_desc").val();
+  var name = utils.escapeHtml($("#new_name").val());
+  var desc = utils.escapeHtml($("#new_desc").val());
 
   utils.disableAll();
   utils.showAlert("info", "", "Adding group...", name);
@@ -166,9 +166,9 @@
   var elem = $(this).attr("id");
   var tr = $(this).closest("tr");
   var id = tr.attr("data-id");
-  var name = tr.find("#name_" + id).val();
+  var name = utils.escapeHtml(tr.find("#name_" + id).val());
   var status = tr.find("#status_" + id).is(":checked") ? 1 : 0;
-  var desc = tr.find("#desc_" + id).val();
+  var desc = utils.escapeHtml(tr.find("#desc_" + id).val());
 
   var done = "edited";
   var notDone = "editing";
@@ -239,7 +239,7 @@
 function deleteGroup() {
   var tr = $(this).closest("tr");
   var id = tr.attr("data-id");
-  var name = tr.find("#name_" + id).val();
+  var name = utils.escapeHtml(tr.find("#name_" + id).val());
 
   utils.disableAll();
   utils.showAlert("info", "", "Deleting group...", name);
```
