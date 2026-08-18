# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1963_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1963_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

import Formatters from '../Formatters'
import DateTime from '../../utils/DateTime'
import Utils from './Utils'

/**
 * ApexCharts Tooltip.Labels Class to draw texts on the tooltip.
 *
 * @module Tooltip.Labels
 **/

export default class Labels {
  constructor(tooltipContext) {
    this.w = tooltipContext.w
    this.ctx = tooltipContext.ctx
    this.ttCtx = tooltipContext
    this.tooltipUtil = new Utils(tooltipContext)
  }

  drawSeriesTexts({ shared = true, ttItems, i = 0, j = null, y1, y2, e }) {
    let w = this.w

    if (w.config.tooltip.custom !== undefined) {
      this.handleCustomTooltip({ i, j, y1, y2, w })
    } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 import Formatters from '../Formatters'
 import DateTime from '../../utils/DateTime'
 import Utils from './Utils'
+import Utilities from '../../utils/Utils'
 
 /**
  * ApexCharts Tooltip.Labels Class to draw texts on the tooltip.
@@ -165,14 +166,14 @@
       if (w.globals.yLabelFormatters[0]) {
         yLbFormatter = w.globals.yLabelFormatters[0]
       } else {
-        yLbFormatter = function(label) {
+        yLbFormatter = function (label) {
           return label
         }
       }
     }
 
     if (typeof yLbTitleFormatter !== 'function') {
-      yLbTitleFormatter = function(label) {
+      yLbTitleFormatter = function (label) {
         return label
       }
     }
@@ -197,6 +198,11 @@
     const w = this.w
     const ttCtx = this.ttCtx
 
+    Object.keys(values).forEach(key => {
+      if (typeof values[key] == 'string')
+        values[key] = Utilities.sanitizeDom(values[key])
+    })
+
     const { val, xVal, xAxisTTVal, zVal } = values
 
     let ttItemsChildren = null
@@ -225,7 +231,7 @@
 
     const ttYLabel = ttItems[t].querySelector('.apexcharts-tooltip-text-label')
     if (ttYLabel) {
-      ttYLabel.innerHTML = seriesName ? seriesName : ''
+      ttYLabel.innerHTML = seriesName ? Utilities.sanitizeDom(seriesName) : ''
     }
     const ttYVal = ttItems[t].querySelector('.apexcharts-tooltip-text-value')
     if (ttYVal) {
```
