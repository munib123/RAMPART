# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in xml
**Pair ID:** 3279_5
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3279_5`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```xml
Lines 1-27 of the vulnerable file.

<?xml version="1.0" encoding="utf-8"?>

<profiles>
    <profile name="jbpm" stencilset="bpmn2.0jbpm">
        <plugin name="ORYX.Plugins.SelectStencilSetPerspective"/>
        <plugin name="ORYX.Plugins.Toolbar"/>
        <plugin name="ORYX.Plugins.JPDLMigration"/>
        <plugin name="ORYX.Plugins.ServiceRepoIntegration"/>
        <plugin name="ORYX.Plugins.SavePlugin"/>
        <plugin name="ORYX.Plugins.ShapeMenuPlugin"/>
        <plugin name="ORYX.Plugins.DataIOEditorPlugin"/>
        <plugin name="ORYX.Plugins.ShapeRepository"/>
        <plugin name="ORYX.Plugins.PropertyWindow"/>
        <plugin name="ORYX.Plugins.CanvasResize"/>
        <plugin name="ORYX.Plugins.View"/>
        <plugin name="ORYX.Plugins.DragDropResize"/>
        <plugin name="ORYX.Plugins.RenameShapes"/>
        <plugin name="ORYX.Plugins.Arrangement"/>
        <plugin name="ORYX.Plugins.Grouping"/>
        <plugin name="ORYX.Plugins.DragDocker"/>
        <plugin name="ORYX.Plugins.AddDocker"/>
        <plugin name="ORYX.Plugins.SelectionFrame"/>
        <plugin name="ORYX.Plugins.ShapeHighlighting"/>
        <plugin name="ORYX.Plugins.Edit"/>
        <plugin name="ORYX.Plugins.Undo"/>
        <plugin name="ORYX.Plugins.KeysMove"/>
        <!--<plugin name="ORYX.Plugins.Layouter.EdgeLayouter"/>-->
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,6 @@
     <profile name="jbpm" stencilset="bpmn2.0jbpm">
         <plugin name="ORYX.Plugins.SelectStencilSetPerspective"/>
         <plugin name="ORYX.Plugins.Toolbar"/>
-        <plugin name="ORYX.Plugins.JPDLMigration"/>
         <plugin name="ORYX.Plugins.ServiceRepoIntegration"/>
         <plugin name="ORYX.Plugins.SavePlugin"/>
         <plugin name="ORYX.Plugins.ShapeMenuPlugin"/>
```
