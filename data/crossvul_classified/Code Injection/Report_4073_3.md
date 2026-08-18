# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in javascript
**Pair ID:** 4073_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4073_3`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```javascript
Lines 229-269 of the vulnerable file.

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
}

function addClient() {
  var ip = $("#select").val();
  var comment = $("#new_comment").val();
  if (ip === "custom") {
    ip = $("#ip-custom").val().trim();
  }

  utils.disableAll();
  utils.showAlert("info", "", "Adding client...", ip);

  if (ip.length === 0) {
    utils.enableAll();
    utils.showAlert("warning", "", "Warning", "Please specify a client IP address");
    return;
  }

  // Validate IP address (may contain CIDR details)
  var ipv6format = ip.includes(":");

  if (!ipv6format && !utils.validateIPv4CIDR(ip)) {
    utils.enableAll();
    utils.showAlert("warning", "", "Warning", "Invalid IPv4 address!");
    return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -246,9 +246,9 @@
 
 function addClient() {
   var ip = $("#select").val();
-  var comment = $("#new_comment").val();
+  var comment = utils.escapeHtml($("#new_comment").val());
   if (ip === "custom") {
-    ip = $("#ip-custom").val().trim();
+    ip = utils.escapeHtml($("#ip-custom").val().trim());
   }
 
   utils.disableAll();
@@ -303,9 +303,9 @@
   var tr = $(this).closest("tr");
   var id = tr.attr("data-id");
   var groups = tr.find("#multiselect_" + id).val();
-  var ip = tr.find("#ip_" + id).text();
-  var name = tr.find("#name_" + id).text();
-  var comment = tr.find("#comment_" + id).val();
+  var ip = utils.escapeHtml(tr.find("#ip_" + id).text());
+  var name = utils.escapeHtml(tr.find("#name_" + id).text());
+  var comment = utils.escapeHtml(tr.find("#comment_" + id).val());
 
   var done = "edited";
   var notDone = "editing";
@@ -370,7 +370,7 @@
   var tr = $(this).closest("tr");
   var id = tr.attr("data-id");
   var ip = tr.find("#ip_" + id).text();
-  var name = tr.find("#name_" + id).text();
+  var name = utils.escapeHtml(tr.find("#name_" + id).text());
 
   if (name.length > 0) {
     ip += " (" + name + ")";
```
