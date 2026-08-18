# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2431_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2431_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1450-1490 of the vulnerable file.

            var url = http.callbackData;
            var data = http.responseText.evalJSON(true);
            var msg = _("Reminder:") + " " + data["summary"] + "\n";
            if (data["startDate"]) {
                msg += _("Start:") + " " + data["startDate"];
                if (parseInt(data["isAllDay"]) == 0)
                    msg += " - " + data["startTime"];
                msg += "\n";
            }
            if (data["dueDate"]) {
                msg += _("Due Date:") + " " + data["dueDate"];
                if (data["dueTime"])
                    msg += " - " + data["dueTime"];
                msg += "\n";
            }
            if (data["location"].length)
                msg += "\n" + _("Location:") + " " + data["location"];
            if (data["description"].length)
                msg += "\n\n" + data["description"];

            window.alert(msg);
            showSelectDialog(data["summary"], _('Snooze for '),
                             { '5': _('5 minutes'),
                               '10': _('10 minutes'),
                               '15': _('15 minutes'),
                               '30': _('30 minutes'),
                               '45': _('45 minutes'),
                               '60': _('1 hour') }, _('OK'),
                             snoozeAlarm, url,
                             '10');
        }
        else
            log("showAlarmCallback ajax error: no data received");
    }
    else {
        log("showAlarmCallback ajax error (" + http.status + "): " + http.url);
    }

    triggerNextAlarm();
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1467,7 +1467,7 @@
             if (data["description"].length)
                 msg += "\n\n" + data["description"];
 
-            window.alert(msg);
+            window.alert(msg.unescapeHTML());
             showSelectDialog(data["summary"], _('Snooze for '),
                              { '5': _('5 minutes'),
                                '10': _('10 minutes'),
@@ -1983,7 +1983,7 @@
     var subdiv = createElement("div", null, null, null, null, newDialog);
     if (title && title.length > 0) {
         var titleh3 = createElement("h3", null, null, null, null, subdiv);
-        titleh3.appendChild(document.createTextNode(title));
+        titleh3.update(title);
     }
     if (legend) {
         if (Object.isElement(legend))
@@ -2141,14 +2141,14 @@
     }
     else {
         var fields = createElement("p", null, []);
-	fields.appendChild(document.createTextNode(label));
+	fields.update(label);
         var select = createElement("select"); //, null, null, { cname: name } );
 	fields.appendChild(select);
         var values = $H(options).keys();
         for (var i = 0; i < values.length; i++) {
             var option = createElement("option", null, null,
                                        { value: values[i] }, null, select);
-            option.appendChild(document.createTextNode(options[values[i]]));
+            option.update(options[values[i]]);
         }
         fields.appendChild(createElement("br"));
 
```
