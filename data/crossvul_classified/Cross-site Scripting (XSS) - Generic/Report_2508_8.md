# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2508_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2508_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 194-234 of the vulnerable file.

		"OMV.data.proxy.Rpc"
	],
	uses: [
		"OMV.module.admin.service.afp.Share"
	],

	hidePagingToolbar: false,
	stateful: true,
	stateId: "b2878122-c1e7-11e0-9bbc-00221568ca88",
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
		text: _("Comment"),
		sortable: true,
		dataIndex: "comment",
		stateId: "comment"
	},{
		xtype: "booleantextcolumn",
		text: _("Read only"),
		sortable: true,
		dataIndex: "readonly",
		stateId: "readonly"
	}],

	initComponent: function() {
		var me = this;
		Ext.apply(me, {
			store: Ext.create("OMV.data.Store", {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -211,11 +211,13 @@
 		resizable: false,
 		iconCls:  Ext.baseCSSPrefix + "grid-cell-booleaniconcolumn-switch"
 	},{
+		xtype: "textcolumn",
 		text: _("Shared folder"),
 		sortable: true,
 		dataIndex: "sharedfoldername",
 		stateId: "sharedfoldername"
 	},{
+		xtype: "textcolumn",
 		text: _("Comment"),
 		sortable: true,
 		dataIndex: "comment",
```
