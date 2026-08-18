# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 3279_1
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3279_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 62-102 of the vulnerable file.

import org.eclipse.bpmn2.di.BPMNShape;
import org.eclipse.bpmn2.di.BpmnDiFactory;
import org.eclipse.dd.dc.Bounds;
import org.eclipse.dd.dc.DcFactory;
import org.eclipse.dd.dc.Point;
import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.resource.ResourceSet;
import org.eclipse.emf.ecore.resource.impl.ResourceSetImpl;
import org.eclipse.emf.ecore.util.FeatureMap;
import org.jboss.drools.impl.DroolsFactoryImpl;
import org.jbpm.designer.bpmn2.resource.JBPMBpmn2ResourceFactoryImpl;
import org.jbpm.designer.bpmn2.resource.JBPMBpmn2ResourceImpl;
import org.jbpm.designer.repository.Asset;
import org.jbpm.designer.repository.AssetBuilderFactory;
import org.jbpm.designer.repository.Repository;
import org.jbpm.designer.repository.impl.AssetBuilder;
import org.jbpm.designer.util.Utils;
import org.jbpm.designer.web.profile.IDiagramProfile;
import org.jbpm.designer.web.profile.IDiagramProfileService;
import org.jbpm.designer.web.profile.impl.JbpmProfileImpl;
import org.jbpm.migration.JbpmMigration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * Transformer for svg process representation to
 * various formats.
 *
 * @author Tihomir Surdilovic
 */
public class TransformerServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger _logger = LoggerFactory.getLogger(TransformerServlet.class);
    private static final String TO_PDF = "pdf";
    private static final String TO_PNG = "png";
    private static final String TO_SVG = "svg";
    private static final String JPDL_TO_BPMN2 = "jpdl2bpmn2";
    private static final String BPMN2_TO_JSON = "bpmn2json";
    private static final String JSON_TO_BPMN2 = "json2bpmn2";
    private static final String HTML_TO_PDF = "html2pdf";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,7 +79,6 @@
 import org.jbpm.designer.web.profile.IDiagramProfile;
 import org.jbpm.designer.web.profile.IDiagramProfileService;
 import org.jbpm.designer.web.profile.impl.JbpmProfileImpl;
-import org.jbpm.migration.JbpmMigration;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 
@@ -96,7 +95,6 @@
     private static final String TO_PDF = "pdf";
     private static final String TO_PNG = "png";
     private static final String TO_SVG = "svg";
-    private static final String JPDL_TO_BPMN2 = "jpdl2bpmn2";
     private static final String BPMN2_TO_JSON = "bpmn2json";
     private static final String JSON_TO_BPMN2 = "json2bpmn2";
     private static final String HTML_TO_PDF = "html2pdf";
@@ -281,37 +279,8 @@
             }
         } else if (transformto != null && transformto.equals(TO_SVG)) {
             storeInRepository(uuid, formattedSvg, transformto, processid, repository);
-        } else if (transformto != null && transformto.equals(JPDL_TO_BPMN2)) {
-            try {
-                String bpmn2 = JbpmMigration.transform(jpdl);
-                Definitions def = ((JbpmProfileImpl) profile).getDefinitions(bpmn2);
-                // add bpmndi info to Definitions with help of gpd
-                addBpmnDiInfo(def, gpd);
-                // hack for now
-                revisitSequenceFlows(def, bpmn2);
-                // another hack if id == name
-                revisitNodeNames(def);
-
-                // get the xml from Definitions
-                ResourceSet rSet = new ResourceSetImpl();
-                rSet.getResourceFactoryRegistry().getExtensionToFactoryMap().put("bpmn2", new JBPMBpmn2ResourceFactoryImpl());
-                JBPMBpmn2ResourceImpl bpmn2resource = (JBPMBpmn2ResourceImpl) rSet.createResource(URI.createURI("virtual.bpmn2"));
-                rSet.getResources().add(bpmn2resource);
-                bpmn2resource.getContents().add(def);
-                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
-                bpmn2resource.save(outputStream, new HashMap<Object, Object>());
-                String fullXmlModel =  outputStream.toString();
-                // convert to json and write response
-                String json = profile.createUnmarshaller().parseModel(fullXmlModel, profile, pp);
-                resp.setCharacterEncoding("UTF-8");
-                resp.setContentType("application/json");
-                resp.getWriter().print(json);
-            } catch(Exception e) {
-                _logger.error(e.getMessage());
-                resp.setContentType("application/json");
-                resp.getWriter().print("{}");
-            }
-        }  else if (transformto != null && transformto.equals(BPMN2_TO_JSON)) {
+
+        } else if (transformto != null && transformto.equals(BPMN2_TO_JSON)) {
             try {
                 if(convertServiceTasks != null && convertServiceTasks.equals("true")) {
                     bpmn2in = bpmn2in.replaceAll("drools:taskName=\".*?\"", "drools:taskName=\"ReadOnlyService\"");
```
