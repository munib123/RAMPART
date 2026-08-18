# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3630_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3630_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 267-307 of the vulnerable file.

    capitalize: function(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }
  };

  horizon.instances = {
    user_decided_length: false,

    getConsoleLog: function(form_element, via_user_submit) {
      if(this.user_decided_length) {
        var data = $(form_element).serialize();
      } else {
        var data = "length=35";
      }

      $.ajax({
        url: $(form_element).attr('action'),
        data: data,
        method: 'get',
        success: function(response_body) {
          $('pre.logs').html(response_body);
        },
        error: function(response) {
          if(via_user_submit) {
            horizon.clearErrorMessages();

            horizon.alert('error', 'There was a problem communicating with the server, please try again.');
          }
        }
      });
    }
  };

  horizon.alert = function (type, message) {
    var template = horizon.templates.compiled_templates["#alert_message_template"],
        params = {"type": type,
                  "type_capitalized": horizon.utils.capitalize(type),
                  "message": message};
    return $(template.render(params)).prependTo("#main_content .messages");
  };

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -284,7 +284,7 @@
         data: data,
         method: 'get',
         success: function(response_body) {
-          $('pre.logs').html(response_body);
+          $('pre.logs').text(response_body);
         },
         error: function(response) {
           if(via_user_submit) {
```
