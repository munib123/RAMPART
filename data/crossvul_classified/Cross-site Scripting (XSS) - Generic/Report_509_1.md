# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 509_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `509_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 1-31 of the vulnerable file.

package org.hswebframework.web.workflow.web;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.activiti.bpmn.converter.BpmnXMLConverter;
import org.activiti.bpmn.model.BpmnModel;
import org.activiti.editor.language.json.converter.BpmnJsonConverter;
import org.activiti.engine.RepositoryService;
import org.activiti.engine.impl.persistence.entity.ModelEntity;
import org.activiti.engine.repository.Deployment;
import org.activiti.engine.repository.Model;
import org.activiti.engine.repository.ModelQuery;
import org.apache.batik.transcoder.TranscoderException;
import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscoderOutput;
import org.apache.batik.transcoder.image.PNGTranscoder;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.hswebframework.ezorm.core.PropertyWrapper;
import org.hswebframework.ezorm.core.SimplePropertyWrapper;
import org.hswebframework.ezorm.core.param.TermType;
import org.hswebframework.web.NotFoundException;
import org.hswebframework.web.authorization.Permission;
import org.hswebframework.web.authorization.annotation.Authorize;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,7 @@
 import io.swagger.annotations.Api;
 import io.swagger.annotations.ApiOperation;
 import io.swagger.annotations.ApiParam;
+import lombok.SneakyThrows;
 import lombok.extern.slf4j.Slf4j;
 import org.activiti.bpmn.converter.BpmnXMLConverter;
 import org.activiti.bpmn.model.BpmnModel;
@@ -33,6 +34,7 @@
 import org.hswebframework.web.commons.entity.PagerResult;
 import org.hswebframework.web.commons.entity.param.QueryParamEntity;
 import org.hswebframework.web.controller.message.ResponseMessage;
+import org.hswebframework.web.workflow.enums.ModelType;
 import org.hswebframework.web.workflow.util.QueryUtils;
 import org.hswebframework.web.workflow.web.request.ModelCreateRequest;
 import org.springframework.beans.factory.annotation.Autowired;
@@ -132,58 +134,51 @@
     @GetMapping(value = "export/{modelId}/{type}")
     @ApiOperation("导出模型")
     @Authorize(action = "export")
+    @SneakyThrows
     public void export(@PathVariable("modelId") @ApiParam("模型ID") String modelId,
-                       @PathVariable("type") @ApiParam(value = "类型", allowableValues = "bpmn,json", example = "json") String type,
+                       @PathVariable("type") @ApiParam(value = "类型", allowableValues = "bpmn,json", example = "json")
+                               ModelType type,
                        @ApiParam(hidden = true) HttpServletResponse response) {
-        try {
-            Model modelData = repositoryService.getModel(modelId);
-            BpmnJsonConverter jsonConverter = new BpmnJsonConverter();
-            byte[] modelEditorSource = repositoryService.getModelEditorSource(modelData.getId());
-
-            JsonNode editorNode = new ObjectMapper().readTree(modelEditorSource);
-            BpmnModel bpmnModel = jsonConverter.convertToBpmnModel(editorNode);
-
-            // 处理异常
-            if (bpmnModel.getMainProcess() == null) {
-                response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
-                response.getOutputStream().println("no main process, can't export for dimension: " + type);
-                response.flushBuffer();
-                return;
-            }
-
-            String filename = "";
-            byte[] exportBytes = null;
-
-            String mainProcessId = bpmnModel.getMainProcess().getId();
-
-            if ("bpmn".equals(type)) {
-
-                BpmnXMLConverter xmlConverter = new BpmnXMLConverter();
-                exportBytes = xmlConverter.convertToXML(bpmnModel);
-
-                filename = mainProcessId + ".bpmn20.xml";
-            } else if ("json".equals(type)) {
-
-                exportBytes = modelEditorSource;
-                filename = mainProcessId + ".json";
-
-            } else {
-                throw new UnsupportedOperationException("不支持的格式:" + type);
-            }
-
-            response.setCharacterEncoding("UTF-8");
-            response.setContentType("application/octet-stream");
-            response.setHeader("Content-Disposition", "attachment; filename=" + URLEncoder.encode(filename, "UTF-8"));
-
-            /*创建输入流*/
-            try (ByteArrayInputStream in = new ByteArrayInputStream(exportBytes)) {
-                IOUtils.copy(in, response.getOutputStream());
-                response.flushBuffer();
-                in.close();
-            }
-
-        } catch (Exception e) {
-            log.error("导出model的xml文件失败：modelId={}, type={}", modelId, type, e);
+        Model modelData = repositoryService.getModel(modelId);
+        if (modelData == null) {
+            throw new NotFoundException("模型不存在");
+        }
+        BpmnJsonConverter jsonConverter = new BpmnJsonConverter();
+        byte[] modelEditorSource = repositoryService.getModelEditorSource(modelData.getId());
+
+        JsonNode editorNode = new ObjectMapper().readTree(modelEditorSource);
+        BpmnModel bpmnModel = jsonConverter.convertToBpmnModel(editorNode);
+
+        // 处理异常
+        if (bpmnModel.getMainProcess() == null) {
+            throw new UnsupportedOperationException("无法导出模型文件:" + type);
+        }
+
+        String filename = "";
+        byte[] exportBytes = null;
+
+        String mainProcessId = bpmnModel.getMainProcess().getId();
+
+        if (type == ModelType.bpmn) {
+            BpmnXMLConverter xmlConverter = new BpmnXMLConverter();
+            exportBytes = xmlConverter.convertToXML(bpmnModel);
+            filename = mainProcessId + ".bpmn20.xml";
+        } else if (type == ModelType.json) {
+            exportBytes = modelEditorSource;
+            filename = mainProcessId + ".json";
+
+        } else {
+            throw new UnsupportedOperationException("不支持的格式:" + type);
+        }
+
+        response.setCharacterEncoding("UTF-8");
+        response.setContentType("application/octet-stream");
+        response.setHeader("Content-Disposition", "attachment; filename=" + URLEncoder.encode(filename, "UTF-8"));
+
+        /*创建输入流*/
+        try (ByteArrayInputStream in = new ByteArrayInputStream(exportBytes)) {
+            IOUtils.copy(in, response.getOutputStream());
+            response.flushBuffer();
         }
     }
 
```
