# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2508_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2508_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 254-294 of the vulnerable file.

		"OMV.window.Execute"
	],
	uses: [
		"OMV.module.admin.service.clamav.Job"
	],

	hidePagingToolbar: false,
	stateful: true,
	stateId: "f8a8cf1c-a107-11e1-a5a0-00221568ca88",
	columns: [{
		xtype: "booleaniconcolumn",
		text: _("Enabled"),
		sortable: true,
		dataIndex: "enable",
		stateId: "enable",
		align: "center",
		width: 80,
		resizable: false,
		iconCls:  Ext.baseCSSPrefix + "grid-cell-booleaniconcolumn-switch"
	},{
		text: _("Shared folder"),
		sortable: true,
		dataIndex: "sharedfoldername",
		stateId: "sharedfoldername"
	},{
		text: _("Minute"),
		sortable: true,
		dataIndex: "minute",
		stateId: "minute",
		renderer: function(value, metaData, record) {
			var everynminute = record.get("everynminute");
			if(everynminute == true) {
				value = "*/" + value;
			}
			return value;
		}
	},{
		text: _("Hour"),
		sortable: true,
		dataIndex: "hour",
		stateId: "hour",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -271,6 +271,7 @@
 		resizable: false,
 		iconCls:  Ext.baseCSSPrefix + "grid-cell-booleaniconcolumn-switch"
 	},{
+		xtype: "textcolumn",
 		text: _("Shared folder"),
 		sortable: true,
 		dataIndex: "sharedfoldername",
@@ -329,6 +330,7 @@
 		stateId: "dayofweek",
 		renderer: OMV.util.Format.arrayRenderer(Date.mapDayOfWeek)
 	},{
+		xtype: "textcolumn",
 		text: _("Comment"),
 		sortable: true,
 		dataIndex: "comment",
```
