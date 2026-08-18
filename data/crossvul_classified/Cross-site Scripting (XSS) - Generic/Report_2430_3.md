# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2430_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2430_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 86-126 of the vulnerable file.

                        $(cells[4]).update(contact["c_telephonenumber"]);
                    }
                }

                // Add extra rows
                for (var j = i; j < data.length; j++) {
                    var contact = data[j];
                    var row = createElement("tr",
                                            contact["c_name"],
                                            contact["c_component"],
                                            null,
                                            { categories: contact["c_categories"],
                                              contactname: contact["c_cn"] },
                                            tbody);
                    var cell = createElement("td",
                                             null,
                                             ( "displayName" ),
                                             null,
                                             null,
                                             row);
                    cell.appendChild(document.createTextNode(contact["c_cn"]));
                    cell.title = contact["c_cn"];

                    cell = document.createElement("td");
                    row.appendChild(cell);
                    if (contact["c_mail"]) {
                        cell.appendChild(document.createTextNode(contact["c_mail"]));
                        cell.title = contact["c_mail"];
                    }

                    if (fullView) {
                        cell = document.createElement("td");
                        row.appendChild(cell);
                        if (contact["c_screenname"])
                            cell.appendChild(document.createTextNode(contact["c_screenname"]));

                        cell = document.createElement("td");
                        row.appendChild(cell);
                        if (contact["c_o"])
                            cell.appendChild(document.createTextNode(contact["c_o"]));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,13 +103,13 @@
                                              null,
                                              null,
                                              row);
-                    cell.appendChild(document.createTextNode(contact["c_cn"]));
+                    cell.update(contact["c_cn"]);
                     cell.title = contact["c_cn"];
 
                     cell = document.createElement("td");
                     row.appendChild(cell);
                     if (contact["c_mail"]) {
-                        cell.appendChild(document.createTextNode(contact["c_mail"]));
+                        cell.update(contact["c_mail"]);
                         cell.title = contact["c_mail"];
                     }
 
@@ -117,17 +117,17 @@
                         cell = document.createElement("td");
                         row.appendChild(cell);
                         if (contact["c_screenname"])
-                            cell.appendChild(document.createTextNode(contact["c_screenname"]));
+                            cell.update(contact["c_screenname"]);
 
                         cell = document.createElement("td");
                         row.appendChild(cell);
                         if (contact["c_o"])
-                            cell.appendChild(document.createTextNode(contact["c_o"]));
+                            cell.update(contact["c_o"]);
 
                         cell = document.createElement("td");
                         row.appendChild(cell);
                         if (contact["c_telephonenumber"])
-                            cell.appendChild(document.createTextNode(contact["c_telephonenumber"]));
+                            cell.update(contact["c_telephonenumber"]);
                     }
                 }
             }
```
