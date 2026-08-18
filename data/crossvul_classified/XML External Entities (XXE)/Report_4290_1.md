# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in xml
**Pair ID:** 4290_1
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4290_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```xml
Lines 1-29 of the vulnerable file.

<?xml version="1.0" encoding="UTF-8"?>
<document>
	<properties>
		<title>MPXJ Changes</title>
		<author email="jon.iles@bcs.org.uk">Jon Iles</author>
	</properties>
	<body>
		<release date="git master" version="8.1.4">
			<action dev="joniles" type="update">Import milestone constraints from Asta schedules (Contributed by Dave McKay)</action>
			<action dev="joniles" type="update">Handle elapsed durations in Asta schedules (Based on a contribution by Dave McKay)</action>
			<action dev="joniles" type="update">Correctly determine the constraint type for tasks with ALAP placement with or without predecessors when reading from from Asta schedules (Contributed by Dave McKay)</action>
			<action dev="joniles" type="update">Gracefully handle a missing table name when reading an XER file.</action>
			<action dev="joniles" type="update">Gracefully handle a unexpected calendar data when reading an XER file.</action>
			<action dev="joniles" type="update">Correctly handle XER files with multi-byte character encoding.</action>
			<action dev="joniles" type="update">Ensure project calendars are read from PMXML files.</action>
			<action dev="joniles" type="add">Added readAll methods to PrimaveraPMFileWriter to allow all projects contained in a PMXML file to be read in a single pass.</action>
		</release>
		<release date="25/06/2020" version="8.1.3">
			<action dev="joniles" type="update">Improve reliability when reading custom field values from certain MPP12 files.</action>
			<action dev="joniles" type="update">Improve accuracy of activity percent complete when reading from certain XER files or P6 databases.</action>
			<action dev="joniles" type="update">Improve accuracy of WBS percent complete when reading from certain XER files or P6 databases.</action>
			<action dev="joniles" type="update">Improve accuracy of task durations when reading Asta schedules.</action>
			<action dev="joniles" type="update">Fix an issue handling the end date of calendar exceptions when reading Asta schedules.</action>
			<action dev="joniles" type="update">Fix an issue with correctly identifying the calendar applied to summary tasks when reading Asta schedules.</action>
			<action dev="joniles" type="update">Populate percent complete, duration, actual start, actual finish, early start, late start, early finish and late finish attributes for summary tasks when reading Asta schedules.</action>
			<action dev="joniles" type="update">The percent complete value reported for tasks when reading Asta schedules is now Duration Percent Complete. The Overall Percent Complete value originally being returned is available in a custom field. </action>
		</release>
		<release date="18/06/2020" version="8.1.2">
			<action dev="joniles" type="update">Improve detection of unusual MSPDI file variants.</action>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,7 @@
 	</properties>
 	<body>
 		<release date="git master" version="8.1.4">
+			<action dev="joniles" type="update">XXE security vulnerability</action>
 			<action dev="joniles" type="update">Import milestone constraints from Asta schedules (Contributed by Dave McKay)</action>
 			<action dev="joniles" type="update">Handle elapsed durations in Asta schedules (Based on a contribution by Dave McKay)</action>
 			<action dev="joniles" type="update">Correctly determine the constraint type for tasks with ALAP placement with or without predecessors when reading from from Asta schedules (Contributed by Dave McKay)</action>
```
