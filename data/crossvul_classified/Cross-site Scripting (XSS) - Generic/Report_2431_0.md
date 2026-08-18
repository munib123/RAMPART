# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2431_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2431_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 248-288 of the vulnerable file.

                        if (nodes[i].recurrenceTime) {
                            cname += '/occurence' + nodes[i].recurrenceTime;
                        }
                        if (!sortedNodes[calendar]) {
                            sortedNodes[calendar] = [];
                            calendars.push(calendar);
                        }
                        if (sortedNodes[calendar].indexOf(cname) < 0) {
                            // Build list item element for confirmation dialog
                            var itemElement = new Element('li');
                            var colorBox = new Element('div', {'class': 'colorBox calendarFolder' + nodes[i].calendar});
                            var content = '';
                            if (nodes[i].tagName == 'TR') {
                                var cell = nodes[i].down('td span');
                                content = cell.allTextContent(); // extract the first column only
                            }
                            else {
                                content = nodes[i].allTextContent();
                            }
                            itemElement.appendChild(colorBox);
                            itemElement.appendChild(new Element('span').update(content));
                            if (nodes[i].startDate) {
                                var startDate = new Date(nodes[i].startDate*1000);
                                var dateElement = new Element('div', {'class': 'muted'});
                                var date;
                                if (typeof nodes[i].hour == 'undefined')
                                    date = startDate.toLocaleDateString(localeCode);
                                else
                                    date = startDate.toLocaleString(localeCode);
                                dateElement.update(date);
                                itemElement.appendChild(dateElement);
                            }
                            events.push(itemElement);
                            sortedNodes[calendar].push(cname);
                        }
                    }
                }
                // Update global arrays
                for (i = 0; i < calendars.length; i++) {
                    calendarsOfEventsToDelete.push(calendars[i]);
                    eventsToDelete.push(sortedNodes[calendars[i]]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -265,7 +265,7 @@
                                 content = nodes[i].allTextContent();
                             }
                             itemElement.appendChild(colorBox);
-                            itemElement.appendChild(new Element('span').update(content));
+                            itemElement.appendChild(new Element('span').update(content.escapeHTML()));
                             if (nodes[i].startDate) {
                                 var startDate = new Date(nodes[i].startDate*1000);
                                 var dateElement = new Element('div', {'class': 'muted'});
@@ -332,7 +332,7 @@
                             }
                         }
                         itemElement.appendChild(colorBox);
-                        itemElement.appendChild(new Element('span').update(content));
+                        itemElement.appendChild(new Element('span').update(content.escapeHTML()));
                         if (selectedCalendarCell[i].startDate) {
                             var startDate = new Date(selectedCalendarCell[i].startDate*1000);
                             var dateElement = new Element('div', {'class': 'muted'});
```
