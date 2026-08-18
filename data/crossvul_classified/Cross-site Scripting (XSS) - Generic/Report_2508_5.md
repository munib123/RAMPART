# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2508_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2508_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 421-461 of the vulnerable file.


/**
 * @class OMV.module.admin.service.iscsitarget.target.LUNs
 * @derived OMV.workspace.grid.Panel
 */
Ext.define("OMV.module.admin.service.iscsitarget.target.LUNs", {
	extend: "OMV.workspace.grid.Panel",
	requires: [
		"OMV.data.Store",
		"OMV.data.Model"
	],
	uses: [
		"OMV.module.admin.service.iscsitarget.target.LUN"
	],

	title: _("LUN"),
	mode: "local",
	stateful: true,
	stateId: "3107db90-c1e9-11e0-90c8-00221568ca88",
	columns: [{
		text: _("Id"),
		sortable: true,
		dataIndex: "id",
		stateId: "id"
	},{
		text: _("Device"),
		sortable: true,
		dataIndex: "devicefile",
		stateId: "devicefile"
	},{
		text: _("SCSI Id."),
		sortable: true,
		dataIndex: "scsiid",
		stateId: "scsiid"
	},{
		text: _("SCSI serial no."),
		sortable: true,
		dataIndex: "scsisn",
		stateId: "scsisn"
	},{
		xtype: "mapcolumn",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -438,21 +438,25 @@
 	stateful: true,
 	stateId: "3107db90-c1e9-11e0-90c8-00221568ca88",
 	columns: [{
+		xtype: "textcolumn",
 		text: _("Id"),
 		sortable: true,
 		dataIndex: "id",
 		stateId: "id"
 	},{
+		xtype: "textcolumn",
 		text: _("Device"),
 		sortable: true,
 		dataIndex: "devicefile",
 		stateId: "devicefile"
 	},{
+		xtype: "textcolumn",
 		text: _("SCSI Id."),
 		sortable: true,
 		dataIndex: "scsiid",
 		stateId: "scsiid"
 	},{
+		xtype: "textcolumn",
 		text: _("SCSI serial no."),
 		sortable: true,
 		dataIndex: "scsisn",
@@ -635,21 +639,25 @@
 	stateful: true,
 	stateId: "15e18b72-c1e9-11e0-a91c-00221568ca88",
 	columns: [{
+		xtype: "textcolumn",
 		text: _("IQN"),
 		sortable: true,
 		dataIndex: "iqn",
 		stateId: "iqn"
 	},{
+		xtype: "textcolumn",
 		text: _("Alias"),
 		sortable: true,
 		dataIndex: "alias",
 		stateId: "alias"
 	},{
+		xtype: "textcolumn",
 		text: _("Max. connections"),
 		sortable: true,
 		dataIndex: "maxconnections",
 		stateId: "maxconnections"
 	},{
+		xtype: "textcolumn",
 		text: _("Comment"),
 		sortable: true,
 		dataIndex: "comment",
```
