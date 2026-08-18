# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1963_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1963_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 172-212 of the vulnerable file.

            elMarker.innerHTML = w.config.legend.markers.customHTML[i]()
          }
        } else {
          elMarker.innerHTML = w.config.legend.markers.customHTML()
        }
      }

      Graphics.setAttrs(elMarker, {
        rel: i + 1,
        'data:collapsed': collapsedSeries || ancillaryCollapsedSeries
      })

      if (collapsedSeries || ancillaryCollapsedSeries) {
        elMarker.classList.add('apexcharts-inactive-legend')
      }

      let elLegend = document.createElement('div')

      let elLegendText = document.createElement('span')
      elLegendText.classList.add('apexcharts-legend-text')
      elLegendText.innerHTML = Array.isArray(text) ? text.join(' ') : text

      let textColor = w.config.legend.labels.useSeriesColors
        ? w.globals.colors[i]
        : w.config.legend.labels.colors

      if (!textColor) {
        textColor = w.config.chart.foreColor
      }

      elLegendText.style.color = textColor

      elLegendText.style.fontSize = parseFloat(w.config.legend.fontSize) + 'px'
      elLegendText.style.fontWeight = w.config.legend.fontWeight
      elLegendText.style.fontFamily = fontFamily || w.config.chart.fontFamily

      Graphics.setAttrs(elLegendText, {
        rel: i + 1,
        i,
        'data:default-text': encodeURIComponent(text),
        'data:collapsed': collapsedSeries || ancillaryCollapsedSeries
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -189,7 +189,7 @@
 
       let elLegendText = document.createElement('span')
       elLegendText.classList.add('apexcharts-legend-text')
-      elLegendText.innerHTML = Array.isArray(text) ? text.join(' ') : text
+      elLegendText.innerHTML = Array.isArray(text) ? Utils.sanitizeDom(text.join(' ')) : Utils.sanitizeDom(text)
 
       let textColor = w.config.legend.labels.useSeriesColors
         ? w.globals.colors[i]
```
