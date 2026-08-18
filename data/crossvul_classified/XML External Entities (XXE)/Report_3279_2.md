# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in xml
**Pair ID:** 3279_2
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3279_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```xml
Lines 331-371 of the vulnerable file.

            </aggregation>

            <aggregation>
              <removeIncluded>false</removeIncluded>
              <insertNewLine>true</insertNewLine>
              <includes>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/css/sprites/toolbar-images-sprite.css</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/css/sprites/palette-images-sprite.css</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/css/sprites/simulation-images-sprite.css</include>
              </includes>
              <output>${project.build.directory}/classes/org/jbpm/designer/public/css/sprites/sprite-stylesheets.css</output>
            </aggregation>

            <aggregation>
              <removeIncluded>false</removeIncluded>
              <insertNewLine>true</insertNewLine>
              <includes>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/selectssperspective-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/toolbar-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/processinfo-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/jpdlmigration-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/servicerepo-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/saveplugin-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/shapemenu-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/dataioeditor-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/shaperepository.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/propertywindow-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/canvasResize-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/view-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/dragdropresize-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/renameShapes-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/undo-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/arrangement-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/grouping-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/dragDocker-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/addDocker-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/selectionframe-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/shapeHighlighting-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/edit-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/keysMove-min.js</include>
                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/selectssperspective-min.js</include>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -348,7 +348,6 @@
                 <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/selectssperspective-min.js</include>
                 <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/toolbar-min.js</include>
                 <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/processinfo-min.js</include>
-                <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/jpdlmigration-min.js</include>
                 <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/servicerepo-min.js</include>
                 <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/saveplugin-min.js</include>
                 <include>${project.build.directory}/classes/org/jbpm/designer/public/js/Plugins/shapemenu-min.js</include>
```
