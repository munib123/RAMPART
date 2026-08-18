# CrossVul Fix Pair: Improper Neutralization of Formula Elements in a CSV File in javascript
**Pair ID:** 4279_2
**Vulnerability Class:** Improper Neutralization of Formula Elements in a CSV File
**CWE:** CWE-1236
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4279_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Formula Elements in a CSV File - User-provided data is often saved to traditional databases.

## Vulnerable Code
```javascript
Lines 199-239 of the vulnerable file.

    })
}

// Exports campaign results as a CSV file
function exportAsCSV(scope) {
    exportHTML = $("#exportButton").html()
    var csvScope = null
    var filename = campaign.name + ' - ' + capitalize(scope) + '.csv'
    switch (scope) {
        case "results":
            csvScope = campaign.results
            break;
        case "events":
            csvScope = campaign.timeline
            break;
    }
    if (!csvScope) {
        return
    }
    $("#exportButton").html('<i class="fa fa-spinner fa-spin"></i>')
    var csvString = Papa.unparse(csvScope, {})
    var csvData = new Blob([csvString], {
        type: 'text/csv;charset=utf-8;'
    });
    if (navigator.msSaveBlob) {
        navigator.msSaveBlob(csvData, filename);
    } else {
        var csvURL = window.URL.createObjectURL(csvData);
        var dlLink = document.createElement('a');
        dlLink.href = csvURL;
        dlLink.setAttribute('download', filename)
        document.body.appendChild(dlLink)
        dlLink.click();
        document.body.removeChild(dlLink)
    }
    $("#exportButton").html(exportHTML)
}

function replay(event_idx) {
    request = campaign.timeline[event_idx]
    details = JSON.parse(request.details)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -216,7 +216,9 @@
         return
     }
     $("#exportButton").html('<i class="fa fa-spinner fa-spin"></i>')
-    var csvString = Papa.unparse(csvScope, {})
+    var csvString = Papa.unparse(csvScope, {
+        'escapeFormulae': true
+    })
     var csvData = new Blob([csvString], {
         type: 'text/csv;charset=utf-8;'
     });
```
