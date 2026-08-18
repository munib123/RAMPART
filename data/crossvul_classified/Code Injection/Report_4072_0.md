# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in javascript
**Pair ID:** 4072_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4072_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```javascript
Lines 286-326 of the vulnerable file.

        utils.showAlert("success", "fas fa-plus", "Successfully added client", ip);
        reloadClientSuggestions();
        table.ajax.reload(null, false);
      } else {
        utils.showAlert("error", "", "Error while adding new client", response.message);
      }
    },
    error: function (jqXHR, exception) {
      utils.enableAll();
      utils.showAlert("error", "", "Error while adding new client", jqXHR.responseText);
      console.log(exception); // eslint-disable-line no-console
    }
  });
}

function editClient() {
  var elem = $(this).attr("id");
  var tr = $(this).closest("tr");
  var id = tr.attr("data-id");
  var groups = tr.find("#multiselect_" + id).val();
  var ip = tr.find("#ip_" + id).text();
  var name = utils.escapeHtml(tr.find("#name_" + id).text());
  var comment = utils.escapeHtml(tr.find("#comment_" + id).val());

  var done = "edited";
  var notDone = "editing";
  switch (elem) {
    case "multiselect_" + id:
      done = "edited groups of";
      notDone = "editing groups of";
      break;
    case "comment_" + id:
      done = "edited comment of";
      notDone = "editing comment of";
      break;
    default:
      alert("bad element or invalid data-id!");
      return;
  }

  if (name.length > 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -303,7 +303,7 @@
   var tr = $(this).closest("tr");
   var id = tr.attr("data-id");
   var groups = tr.find("#multiselect_" + id).val();
-  var ip = tr.find("#ip_" + id).text();
+  var ip = utils.escapeHtml(tr.find("#ip_" + id).text());
   var name = utils.escapeHtml(tr.find("#name_" + id).text());
   var comment = utils.escapeHtml(tr.find("#comment_" + id).val());
 
```
