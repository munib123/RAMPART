# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2315_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2315_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1838-1878 of the vulnerable file.

        if (timeInt < 10) {
            timeInt = '0' + timeInt;
        }

        return hours + ':' + minutes + ':' + timeInt;
    }

    /* Constructs the log table out of the retrieved server data */
    function buildLogTable(data) {
        var rows = data.rows;
        var cols = [];
        var $table = $('<table class="sortable"></table>');
        var $tBody, $tRow, $tCell;

        $('#logTable').html($table);

        var formatValue = function (name, value) {
            if (name == 'user_host') {
                return value.replace(/(\[.*?\])+/g, '');
            }
            return value;
        };

        for (var i = 0, l = rows.length; i < l; i++) {
            if (i === 0) {
                $.each(rows[0], function (key, value) {
                    cols.push(key);
                });
                $table.append('<thead>' +
                              '<tr><th class="nowrap">' + cols.join('</th><th class="nowrap">') + '</th></tr>' +
                              '</thead>'
                );

                $table.append($tBody = $('<tbody></tbody>'));
            }

            $tBody.append($tRow = $('<tr class="noclick"></tr>'));
            var cl = '';
            for (var j = 0, ll = cols.length; j < ll; j++) {
                // Assuming the query column is the second last
                if (j == cols.length - 2 && rows[i][cols[j]].match(/^SELECT/i)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1855,7 +1855,7 @@
             if (name == 'user_host') {
                 return value.replace(/(\[.*?\])+/g, '');
             }
-            return value;
+            return escapeHtml(value);
         };
 
         for (var i = 0, l = rows.length; i < l; i++) {
@@ -2011,7 +2011,7 @@
             for (i = 0, l = data.explain.length; i < l; i++) {
                 explain += '<div class="explain-' + i + '"' + (i > 0 ?  'style="display:none;"' : '') + '>';
                 $.each(data.explain[i], function (key, value) {
-                    value = (value === null) ? 'null' : value;
+                    value = (value === null) ? 'null' : escapeHtml(value);
 
                     if (key == 'type' && value.toLowerCase() == 'all') {
                         value = '<span class="attention">' + value + '</span>';
```
