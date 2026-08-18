# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 5152_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5152_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 139-179 of the vulnerable file.

        });
        dataTable.setData(values);
    }

    // draw the chart and return the chart object
    chart.draw(dataTable, plotSettings);
    return chart;
}

function drawChart() {
    currentSettings.width = $('#resizer').width() - 20;
    currentSettings.height = $('#resizer').height() - 20;

    // TODO: a better way using .redraw() ?
    if (currentChart !== null) {
        currentChart.destroy();
    }

    var columnNames = [];
    $('select[name="chartXAxis"] option').each(function () {
        columnNames.push($(this).text());
    });
    try {
        currentChart = PMA_queryChart(chart_data, columnNames, currentSettings);
        if (currentChart != null) {
            $('#saveChart').attr('href', currentChart.toImageString());
        }
    } catch (err) {
        PMA_ajaxShowMessage(err.message, false);
    }
}

function getSelectedSeries() {
    var val = $('select[name="chartSeries"]').val() || [];
    var ret = [];
    $.each(val, function (i, v) {
        ret.push(parseInt(v, 10));
    });
    return ret;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,7 +156,7 @@
 
     var columnNames = [];
     $('select[name="chartXAxis"] option').each(function () {
-        columnNames.push($(this).text());
+        columnNames.push(escapeHtml($(this).text()));
     });
     try {
         currentChart = PMA_queryChart(chart_data, columnNames, currentSettings);
```
