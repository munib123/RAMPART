# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2251_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2251_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 891-931 of the vulnerable file.

        if (serie.dataPoints[0].name == 'Processes') {
            serie.dataPoints[0].type = 'proc';
        }

        if ($('input[name="useDivisor"]').prop('checked')) {
            serie.valueDivisor = parseInt($('input[name="valueDivisor"]').val(), 10);
        }

        if ($('input[name="useUnit"]').prop('checked')) {
            serie.unit = $('input[name="valueUnit"]').val();
        }

        var str = serie.display == 'differential' ? ', ' + PMA_messages.strDifferential : '';
        str += serie.valueDivisor ? (', ' + $.sprintf(PMA_messages.strDividedBy, serie.valueDivisor)) : '';
        str += serie.unit ? (', ' + PMA_messages.strUnit + ': ' + serie.unit) : '';

        var newSeries = {
            label: $('#variableInput').val().replace(/_/g, " ")
        };
        newChart.series.push(newSeries);
        $('#seriesPreview').append('- ' + newSeries.label + str + '<br/>');
        newChart.nodes.push(serie);
        $('#variableInput').val('');
        $('input[name="differentialValue"]').prop('checked', true);
        $('input[name="useDivisor"]').prop('checked', false);
        $('input[name="useUnit"]').prop('checked', false);
        $('input[name="useDivisor"]').trigger('change');
        $('input[name="useUnit"]').trigger('change');
        $('select[name="varChartList"]').get(0).selectedIndex = 0;

        $('#clearSeriesLink').show();

        return false;
    });

    $("#variableInput").autocomplete({
        source: variableNames
    });

    /* Initializes the monitor, called only once */
    function initGrid() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -908,7 +908,7 @@
             label: $('#variableInput').val().replace(/_/g, " ")
         };
         newChart.series.push(newSeries);
-        $('#seriesPreview').append('- ' + newSeries.label + str + '<br/>');
+        $('#seriesPreview').append('- ' + escapeHtml(newSeries.label + str) + '<br/>');
         newChart.nodes.push(serie);
         $('#variableInput').val('');
         $('input[name="differentialValue"]').prop('checked', true);
```
