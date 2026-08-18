# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in javascript
**Pair ID:** 4073_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4073_2`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```javascript
Lines 195-236 of the vulnerable file.

    } else {
      $("#resetButton").addClass("hidden");
    }
  });
  $("#resetButton").on("click", function () {
    table.order([[0, "asc"]]).draw();
    $("#resetButton").addClass("hidden");
  });

  // Disable autocorrect in the search box
  var input = document.querySelector("input[type=search]");
  if (input !== null) {
    input.setAttribute("autocomplete", "off");
    input.setAttribute("autocorrect", "off");
    input.setAttribute("autocapitalize", "off");
    input.setAttribute("spellcheck", false);
  }
}

function addAdlist() {
  var address = $("#new_address").val();
  var comment = $("#new_comment").val();

  utils.disableAll();
  utils.showAlert("info", "", "Adding adlist...", address);

  if (address.length === 0) {
    utils.showAlert("warning", "", "Warning", "Please specify an adlist address");
    return;
  }

  $.ajax({
    url: "scripts/pi-hole/php/groups.php",
    method: "post",
    dataType: "json",
    data: {
      action: "add_adlist",
      address: address,
      comment: comment,
      token: token
    },
    success: function (response) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -212,8 +212,8 @@
 }
 
 function addAdlist() {
-  var address = $("#new_address").val();
-  var comment = $("#new_comment").val();
+  var address = utils.escapeHtml($("#new_address").val());
+  var comment = utils.escapeHtml($("#new_comment").val());
 
   utils.disableAll();
   utils.showAlert("info", "", "Adding adlist...", address);
@@ -258,9 +258,9 @@
   var tr = $(this).closest("tr");
   var id = tr.attr("data-id");
   var status = tr.find("#status_" + id).is(":checked") ? 1 : 0;
-  var comment = tr.find("#comment_" + id).val();
+  var comment = utils.escapeHtml(tr.find("#comment_" + id).val());
   var groups = tr.find("#multiselect_" + id).val();
-  var address = tr.find("#address_" + id).text();
+  var address = utils.escapeHtml(tr.find("#address_" + id).text());
 
   var done = "edited";
   var notDone = "editing";
@@ -338,7 +338,7 @@
 function deleteAdlist() {
   var tr = $(this).closest("tr");
   var id = tr.attr("data-id");
-  var address = tr.find("#address_" + id).text();
+  var address = utils.escapeHtml(tr.find("#address_" + id).text());
 
   utils.disableAll();
   utils.showAlert("info", "", "Deleting adlist...", address);
```
