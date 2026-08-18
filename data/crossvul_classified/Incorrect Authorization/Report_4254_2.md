# CrossVul Fix Pair: Incorrect Authorization in java
**Pair ID:** 4254_2
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4254_2`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 1-27 of the vulnerable file.

package com.zrlog.service;

import com.hibegin.common.util.http.HttpUtil;
import com.hibegin.common.util.http.handle.HttpJsonArrayHandle;
import com.zrlog.common.Constants;
import com.zrlog.common.response.UploadFileResponse;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UploadService {

    private static final Logger LOGGER = Logger.getLogger(UploadService.class);

    public UploadFileResponse getCloudUrl(String contextPath, String uri, String finalFilePath, HttpServletRequest request) {
        UploadFileResponse uploadFileResponse = new UploadFileResponse();
        // try push to cloud
        Map<String, String[]> map = new HashMap<>();
        map.put("fileInfo", new String[]{finalFilePath + "," + uri});
        map.put("name", new String[]{"uploadService"});
        String url;
        try {
            List<Map> urls = HttpUtil.getInstance().sendGetRequest(Constants.pluginServer + "/service", map
                    , new HttpJsonArrayHandle<Map>(), PluginHelper.genHeaderMapByRequest(request)).getT();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
 import com.hibegin.common.util.http.handle.HttpJsonArrayHandle;
 import com.zrlog.common.Constants;
 import com.zrlog.common.response.UploadFileResponse;
+import com.zrlog.web.util.PluginHelper;
 import org.apache.log4j.Logger;
 
 import javax.servlet.http.HttpServletRequest;
@@ -24,7 +25,7 @@
         String url;
         try {
             List<Map> urls = HttpUtil.getInstance().sendGetRequest(Constants.pluginServer + "/service", map
-                    , new HttpJsonArrayHandle<Map>(), PluginHelper.genHeaderMapByRequest(request)).getT();
+                    , new HttpJsonArrayHandle<Map>(), PluginHelper.genHeaderMapByRequest(request, AdminTokenThreadLocal.getUser())).getT();
             if (urls != null && !urls.isEmpty()) {
                 url = (String) urls.get(0).get("url");
                 if (!url.startsWith("https://") && !url.startsWith("http://")) {
```
