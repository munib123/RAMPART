# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in javascript
**Pair ID:** 4073_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4073_4`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```javascript
Lines 301-342 of the vulnerable file.


function addDomain() {
  var action = this.id;
  var tabHref = $('a[data-toggle="tab"][aria-expanded="true"]').attr("href");
  var wildcardEl = $("#wildcard_checkbox");
  var wildcardChecked = wildcardEl.prop("checked");
  var type;

  // current tab's inputs
  var domainRegex, domainEl, commentEl;
  if (tabHref === "#tab_domain") {
    domainRegex = "domain";
    domainEl = $("#new_domain");
    commentEl = $("#new_domain_comment");
  } else if (tabHref === "#tab_regex") {
    domainRegex = "regex";
    domainEl = $("#new_regex");
    commentEl = $("#new_regex_comment");
  }

  var domain = domainEl.val();
  var comment = commentEl.val();

  utils.disableAll();
  utils.showAlert("info", "", "Adding " + domainRegex + "...", domain);

  if (domain.length > 0) {
    // strip "*." if specified by user in wildcard mode
    if (domainRegex === "domain" && wildcardChecked && domain.startsWith("*.")) {
      domain = domain.substr(2);
    }

    // determine list type
    if (domainRegex === "domain" && action === "add2black" && wildcardChecked) {
      type = "3W";
    } else if (domainRegex === "domain" && action === "add2black" && !wildcardChecked) {
      type = "1";
    } else if (domainRegex === "domain" && action === "add2white" && wildcardChecked) {
      type = "2W";
    } else if (domainRegex === "domain" && action === "add2white" && !wildcardChecked) {
      type = "0";
    } else if (domainRegex === "regex" && action === "add2black") {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -318,8 +318,8 @@
     commentEl = $("#new_regex_comment");
   }
 
-  var domain = domainEl.val();
-  var comment = commentEl.val();
+  var domain = utils.escapeHtml(domainEl.val());
+  var comment = utils.escapeHtml(commentEl.val());
 
   utils.disableAll();
   utils.showAlert("info", "", "Adding " + domainRegex + "...", domain);
@@ -385,10 +385,10 @@
   var elem = $(this).attr("id");
   var tr = $(this).closest("tr");
   var id = tr.attr("data-id");
-  var domain = tr.find("#domain_" + id).text();
+  var domain = utils.escapeHtml(tr.find("#domain_" + id).text());
   var type = tr.find("#type_" + id).val();
   var status = tr.find("#status_" + id).is(":checked") ? 1 : 0;
-  var comment = tr.find("#comment_" + id).val();
+  var comment = utils.escapeHtml(tr.find("#comment_" + id).val());
 
   // Show group assignment field only if in full domain management mode
   // if not included, just use the row data.
@@ -485,7 +485,7 @@
 function deleteDomain() {
   var tr = $(this).closest("tr");
   var id = tr.attr("data-id");
-  var domain = tr.find("#domain_" + id).text();
+  var domain = utils.escapeHtml(tr.find("#domain_" + id).text());
   var type = tr.find("#type_" + id).val();
 
   var domainRegex;
```
