# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in xml
**Pair ID:** 3279_4
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3279_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```xml
Lines 17-58 of the vulnerable file.

		<plugin source="loading.js" name="ORYX.Plugins.Loading" core="true" />
		<plugin source="canvasResize.js" name="ORYX.Plugins.CanvasResize">
			<notUsesIn namespace="http://b3mn.org/stencilset/xforms#" />
		</plugin>
		<plugin source="renameShapes.js" name="ORYX.Plugins.RenameShapes" />
		<plugin source="erdfSupport.js" name="ORYX.Plugins.ERDFSupport" />
		<plugin source="jsonSupport.js" name="ORYX.Plugins.JSONSupport">
			<property name="color" value="red" />
		</plugin>
		<plugin source="rdfExport.js" name="ORYX.Plugins.RDFExport" />
		<plugin source="undo.js" name="ORYX.Plugins.Undo" />

		<plugin source="epcSupport.js" name="ORYX.Plugins.EPCSupport">
			<requires namespace="http://b3mn.org/stencilset/epc#" />
		</plugin>

		<plugin source="jpdlSupport.js" name="ORYX.Plugins.JPDLSupport">
			<requires namespace="http://b3mn.org/stencilset/bpmn1.1#" />
			<!-- plugin loads dynamically the needed extension <requires namespace="http://oryx-editor.org/stencilsets/extensions/jbpm#"/> -->
		</plugin>
		
		<plugin source="jpdlmigration.js" name="ORYX.Plugins.JPDLMigration"/>
		<plugin source="servicerepo.js"   name="ORYX.Plugins.ServiceRepoIntegration"/>

		<!-- User Interface Aggregation -->
		<plugin source="bpmn2xforms.js" name="ORYX.Plugins.BPMN2XForms">
			<requires namespace="http://b3mn.org/stencilset/bpmn1.1#" />
		</plugin>

		<plugin source="bpmn2bpel.js" name="ORYX.Plugins.BPMN2BPEL">
			<requires namespace="http://b3mn.org/stencilset/bpmn1.1#" />
		</plugin>

		<plugin source="processLink.js" name="ORYX.Plugins.ProcessLink">
			<requires namespace="http://b3mn.org/stencilset/epc#" />
			<requires namespace="http://b3mn.org/stencilset/bpmn1.1#" />
		</plugin>

		<plugin source="adHocCC.js" name="ORYX.Plugins.AdHocCC">
			<requires namespace="http://b3mn.org/stencilset/bpmnexec#" />
		</plugin>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,8 +34,7 @@
 			<requires namespace="http://b3mn.org/stencilset/bpmn1.1#" />
 			<!-- plugin loads dynamically the needed extension <requires namespace="http://oryx-editor.org/stencilsets/extensions/jbpm#"/> -->
 		</plugin>
-		
-		<plugin source="jpdlmigration.js" name="ORYX.Plugins.JPDLMigration"/>
+
 		<plugin source="servicerepo.js"   name="ORYX.Plugins.ServiceRepoIntegration"/>
 
 		<!-- User Interface Aggregation -->
```
