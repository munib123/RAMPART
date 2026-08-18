# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2429_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2429_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 998-1038 of the vulnerable file.

                    row.hour = startDate.getHourString(); // event is not all day
                row.observe("mousedown", onRowClick);
                row.observe("selectstart", listRowMouseDownHandler);
                if (data[i][3] != null)
                    // Status is defined -- event is readable
                    row.observe("dblclick", editDoubleClickedEvent);

                var td = createElement("td");
                row.appendChild(td);
                td.observe("mousedown", listRowMouseDownHandler, true);
                var colorDiv = createElement("div", false, "colorBox calendarFolder" + calendar);
                td.appendChild(colorDiv);
                colorDiv.update('&nbsp;');
                var span = createElement("span");
                td.appendChild(span);
                span.update(data[i][4]); // title

                td = createElement("td");
                row.appendChild(td);
                td.observe("mousedown", listRowMouseDownHandler, true);
                td.appendChild(document.createTextNode(data[i][21])); // start date

                td = createElement("td");
                row.appendChild(td);
                td.observe("mousedown", listRowMouseDownHandler, true);
                td.appendChild(document.createTextNode(data[i][22])); // end date

                td = createElement("td");
                row.appendChild(td);
                td.observe("mousedown", listRowMouseDownHandler, true);
                if (data[i][7])
                    td.appendChild(document.createTextNode(data[i][7])); // location

                td = createElement("td");
                row.appendChild(td);
                td.observe("mousedown", listRowMouseDownHandler, true);
                td.appendChild(document.createTextNode(data[i][2])); // calendar
            }

            if (sorting["event-header"] && sorting["event-header"].length > 0) {
                var sortHeader = $(sorting["event-header"]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1015,23 +1015,23 @@
                 td = createElement("td");
                 row.appendChild(td);
                 td.observe("mousedown", listRowMouseDownHandler, true);
-                td.appendChild(document.createTextNode(data[i][21])); // start date
+                td.update(data[i][21]); // start date
 
                 td = createElement("td");
                 row.appendChild(td);
                 td.observe("mousedown", listRowMouseDownHandler, true);
-                td.appendChild(document.createTextNode(data[i][22])); // end date
+                td.update(data[i][22]); // end date
 
                 td = createElement("td");
                 row.appendChild(td);
                 td.observe("mousedown", listRowMouseDownHandler, true);
                 if (data[i][7])
-                    td.appendChild(document.createTextNode(data[i][7])); // location
+                    td.update(data[i][7]); // location
 
                 td = createElement("td");
                 row.appendChild(td);
                 td.observe("mousedown", listRowMouseDownHandler, true);
-                td.appendChild(document.createTextNode(data[i][2])); // calendar
+                td.update(data[i][2]); // calendar
             }
 
             if (sorting["event-header"] && sorting["event-header"].length > 0) {
```
