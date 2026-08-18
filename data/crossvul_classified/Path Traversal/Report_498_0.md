# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 498_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `498_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 1-23 of the vulnerable file.

package cc.mrbird.common.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

@Controller
public class CommonController {

    private Logger log = LoggerFactory.getLogger(this.getClass());

    @RequestMapping("common/download")
    public void fileDownload(String fileName, Boolean delete, HttpServletResponse response) throws IOException {
        String realFileName = System.currentTimeMillis() + fileName.substring(fileName.indexOf('_') + 1);
        String filePath = "file/" + fileName;
        File file = new File(filePath);
        response.setHeader("Content-Disposition", "attachment;fileName=" + java.net.URLEncoder.encode(realFileName, "utf-8"));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,7 @@
 package cc.mrbird.common.controller;
 
+import cc.mrbird.common.exception.FileDownloadException;
+import org.apache.commons.lang3.StringUtils;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 import org.springframework.stereotype.Controller;
@@ -16,10 +18,14 @@
     private Logger log = LoggerFactory.getLogger(this.getClass());
 
     @RequestMapping("common/download")
-    public void fileDownload(String fileName, Boolean delete, HttpServletResponse response) throws IOException {
+    public void fileDownload(String fileName, Boolean delete, HttpServletResponse response) throws IOException, FileDownloadException {
+        if (StringUtils.isNotBlank(fileName) && !fileName.endsWith(".xlsx"))
+            throw new FileDownloadException("不支持该类型文件下载");
         String realFileName = System.currentTimeMillis() + fileName.substring(fileName.indexOf('_') + 1);
         String filePath = "file/" + fileName;
         File file = new File(filePath);
+        if (!file.exists())
+            throw new FileDownloadException("文件未找到");
         response.setHeader("Content-Disposition", "attachment;fileName=" + java.net.URLEncoder.encode(realFileName, "utf-8"));
         response.setContentType("multipart/form-data");
         response.setCharacterEncoding("utf-8");
@@ -32,9 +38,8 @@
         } catch (Exception e) {
             log.error("文件下载失败", e);
         } finally {
-            if (delete && file.exists()) {
+            if (delete)
                 Files.delete(Paths.get(filePath));
-            }
         }
     }
 }
```
